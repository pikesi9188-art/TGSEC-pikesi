#!/usr/bin/env python3
"""ACG-FAKA / 异次元专项：指纹、后台路径、callback handle 枚举。

示例:
  python3 tools/acg-faka/bin/acg_probe.py \\
    --base https://tghaopf.com --case tghaopf_20260804 \\
    --storage 案卷/tghaopf_20260804/接管/session/storage_state.json
"""
from __future__ import annotations

import argparse
import json
import re
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

def _kit_ops_dir(start: Path) -> Path:
    here = start.resolve()
    if here.is_file():
        here = here.parent
    for p in (here, *here.parents):
        fang = p / "炼蛊房"
        if (fang / "scope_lib.py").is_file():
            return fang
        ops = p / "tools" / "ops"
        if (ops / "scope_lib.py").is_file():
            return ops
    return here

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT.parents[1]
DICTS = ROOT / "dicts"
OPS = _kit_ops_dir(Path(__file__))
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))

from scope_lib import host_of, in_scope, silent_expand  # noqa: E402


def http_get(url: str, headers: dict | None = None, timeout: int = 20) -> dict:
    hdrs = {"User-Agent": "Mozilla/5.0 大爱仙尊-acg_probe", "Accept": "*/*"}
    if headers:
        hdrs.update(headers)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers=hdrs, method="GET")
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
            body = r.read()[:500_000]
            return {
                "status": r.status,
                "headers": {k.lower(): v for k, v in r.headers.items()},
                "body": body.decode("utf-8", "replace"),
                "len": len(body),
            }
    except urllib.error.HTTPError as e:
        body = e.read()[:200_000] if e.fp else b""
        return {
            "status": e.code,
            "headers": {k.lower(): v for k, v in (e.headers.items() if e.headers else [])},
            "body": body.decode("utf-8", "replace"),
            "len": len(body),
        }
    except Exception as e:
        return {"status": 0, "error": str(e), "body": "", "len": 0}


def fingerprint(base: str) -> dict:
    base = base.rstrip("/")
    markers = {}
    for path in (
        "/",
        "/assets/static/acg.js",
        "/assets/admin/images/login/bg.jpg",
        "/user/api/index/data",
        "/user/api/index/pay",
        "/user/authentication/login",
    ):
        r = http_get(base + path)
        markers[path] = {
            "status": r.get("status"),
            "len": r.get("len"),
            "acg_js": "acg" in (r.get("body") or "").lower()[:2000] if path.endswith("acg.js") else None,
            "title": (re.search(r"<title[^>]*>([^<]+)", r.get("body") or "", re.I) or [None, ""])[1][:80],
        }
    home = markers.get("/") or {}
    is_acg = bool(
        (markers.get("/assets/static/acg.js") or {}).get("status") == 200
        or "acg" in (home.get("title") or "").lower()
    )
    return {"is_acg_faka_likely": is_acg, "markers": markers}


def load_lines(path: Path) -> list[str]:
    if not path.is_file():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line.lstrip("/"))
    return out


def probe_admin(base: str, paths: list[str], storage: Path | None) -> list[dict]:
    base = base.rstrip("/")
    results = []
    # 优先用 playwright+storage 过 CF
    if storage and storage.is_file():
        try:
            from playwright.sync_api import sync_playwright

            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(storage_state=str(storage))
                page = context.new_page()
                page.goto(base + "/", wait_until="domcontentloaded", timeout=60000)
                for rel in paths:
                    url = base + "/" + rel
                    r = page.evaluate(
                        """async (url) => {
                          const resp = await fetch(url, {credentials:'include', redirect:'manual'});
                          const t = await resp.text();
                          const title = (t.match(/<title[^>]*>([^<]+)/i)||[,''])[1].trim();
                          return {status: resp.status, title, len: t.length,
                            loc: resp.headers.get('location')||''};
                        }""",
                        url,
                    )
                    hit = _admin_hit(r)
                    results.append({"path": "/" + rel, **r, "hit": hit})
                    if hit:
                        print(f"  [HIT] /{rel} {r}")
                browser.close()
            return results
        except Exception as e:
            print(f"[*] playwright 失败，回落 urllib: {e}")

    for rel in paths:
        r = http_get(base + "/" + rel)
        title = (re.search(r"<title[^>]*>([^<]+)", r.get("body") or "", re.I) or [None, ""])[1]
        item = {
            "path": "/" + rel,
            "status": r.get("status"),
            "title": title,
            "len": r.get("len"),
            "hit": False,
        }
        item["hit"] = _admin_hit(item)
        results.append(item)
        if item["hit"]:
            print(f"  [HIT] /{rel} status={item['status']} title={title}")
    return results


def _admin_hit(r: dict) -> bool:
    st = r.get("status")
    title = (r.get("title") or "").lower()
    ln = int(r.get("len") or 0)
    if st not in (200, 401, 403):
        return False
    if any(x in title for x in ("请稍候", "just a moment", "404", "not found")):
        return False
    if any(x in title for x in ("登录", "login", "管理", "admin", "后台")):
        return True
    # 静态资源存在
    if st == 200 and ln > 1000 and "login" in (r.get("path") or ""):
        return True
    if st == 200 and ln > 5000 and "小马" not in title and "商店" not in title:
        # 可能是随机后台页
        return "dashboard" in title or "admin" in title or ln < 80000
    return False


def enum_callbacks(base: str, handles: list[str], storage: Path | None) -> list[dict]:
    base = base.rstrip("/")
    # 展开大小写
    expanded = []
    for h in handles:
        expanded.extend({h, h.lower(), h.upper(), h.capitalize()})
    # 去重保序
    seen = set()
    handles2 = []
    for h in expanded:
        if h not in seen:
            seen.add(h)
            handles2.append(h)

    results = []
    fetch = None
    if storage and storage.is_file():
        try:
            from playwright.sync_api import sync_playwright

            pw = sync_playwright().start()
            browser = pw.chromium.launch(headless=True)
            context = browser.new_context(storage_state=str(storage))
            page = context.new_page()
            page.goto(base + "/", wait_until="domcontentloaded", timeout=60000)

            def fetch(url, body="out_trade_no=probe&sign=true"):
                return page.evaluate(
                    """async ({url, body}) => {
                      const resp = await fetch(url, {method:'POST', credentials:'include',
                        headers:{'Content-Type':'application/x-www-form-urlencoded'}, body});
                      const t = await resp.text();
                      return {status: resp.status, body: t.slice(0,300)};
                    }""",
                    {"url": url, "body": body},
                )

            for h in handles2:
                url = f"{base}/user/api/order/callback.{h}"
                r = fetch(url)
                alive = r.get("status") == 200 and "not found" not in (r.get("body") or "").lower()
                # 404 HTML vs JSON sign error
                if "sign error" in (r.get("body") or "") or '"code"' in (r.get("body") or ""):
                    alive = True
                results.append({"handle": h, "url": url, **r, "alive": alive})
                if alive:
                    print(f"  [CB] {h} → {r.get('body','')[:80]}")
            browser.close()
            pw.stop()
            return results
        except Exception as e:
            print(f"[*] callback playwright 失败: {e}")

    for h in handles2:
        url = f"{base}/user/api/order/callback.{h}"
        # POST empty
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        data = b"out_trade_no=probe&sign=true"
        req = urllib.request.Request(
            url,
            data=data,
            method="POST",
            headers={
                "User-Agent": "Mozilla/5.0 大爱仙尊-acg_probe",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
                body = resp.read().decode("utf-8", "replace")[:300]
                st = resp.status
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")[:300] if e.fp else ""
            st = e.code
        except Exception as e:
            body, st = str(e), 0
        alive = st == 200 and (
            "sign error" in body or '"code"' in body or "success" in body.lower()
        )
        results.append({"handle": h, "url": url, "status": st, "body": body, "alive": alive})
        if alive:
            print(f"  [CB] {h} → {body[:80]}")
    return results


def main() -> int:
    ap = argparse.ArgumentParser(description="ACG-FAKA 专项探针")
    ap.add_argument("--base", required=True)
    ap.add_argument("--case", required=True)
    ap.add_argument("--storage", default="")
    ap.add_argument("--admin-dict", default=str(DICTS / "admin_paths.txt"))
    ap.add_argument("--handles-dict", default=str(DICTS / "callback_handles.txt"))
    ap.add_argument("--skip-admin", action="store_true")
    ap.add_argument("--skip-callback", action="store_true")
    ap.add_argument("--skip-scope-check", action="store_true")
    ap.add_argument("--expand-pay-hosts", action="append", default=[], help="支付跳转 host，静默扩权")
    args = ap.parse_args()

    host = host_of(args.base)
    if not args.skip_scope_check and not in_scope(host):
        print(f"[!] {host} 不在 scope", file=sys.stderr)
        return 1

    for h in args.expand_pay_hosts:
        try:
            silent_expand(
                parent=host,
                discovered=[h],
                case=args.case,
                note="acg_probe expand-pay-hosts",
            )
        except ValueError as e:
            print(f"[!] expand {h}: {e}")

    storage = Path(args.storage) if args.storage else None
    fp = fingerprint(args.base)
    print(f"[*] acg_likely={fp['is_acg_faka_likely']}")

    admin = []
    if not args.skip_admin:
        paths = load_lines(Path(args.admin_dict))
        print(f"[*] admin paths={len(paths)}")
        admin = probe_admin(args.base, paths, storage)

    callbacks = []
    if not args.skip_callback:
        handles = load_lines(Path(args.handles_dict))
        print(f"[*] callback handles={len(handles)}")
        callbacks = enum_callbacks(args.base, handles, storage)

    out_dir = (ENGINE / "案卷" if (ENGINE / "案卷").is_dir() else ENGINE / "exports" / "bot-recovery") / args.case / "测绘" / "acg"
    out_dir.mkdir(parents=True, exist_ok=True)
    doc = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "base": args.base,
        "fingerprint": fp,
        "admin_hits": [a for a in admin if a.get("hit")],
        "admin_all": admin,
        "callback_alive": [c for c in callbacks if c.get("alive")],
        "callbacks": callbacks,
    }
    path = out_dir / "acg_probe.json"
    path.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    md = [
        "# ACG probe",
        "",
        f"- acg_likely: **{fp['is_acg_faka_likely']}**",
        f"- admin hits: {len(doc['admin_hits'])}",
        f"- callback alive: {', '.join(c['handle'] for c in doc['callback_alive']) or '无'}",
        "",
    ]
    for a in doc["admin_hits"][:20]:
        md.append(f"- admin `{a['path']}` status={a.get('status')} title={a.get('title')}")
    (out_dir / "ACG_PROBE.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(f"[+] {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
