#!/usr/bin/env python3
"""ACG 共享货上游：发现 domain / Shared 对接 / 橱窗 code 对齐。

对齐 Playbook：传承/ACG共享货上游库存杀伤链.md

示例:
  python3 tools/acg-faka/bin/acg_shared_upstream.py discover \\
    --base https://favip.fjapp.vip --case favip_fjapp_20260804

  python3 tools/acg-faka/bin/acg_shared_upstream.py connect \\
    --upstream https://www.guopi.org --app-id 1291 --app-key KEY --case <案卷>

  python3 tools/acg-faka/bin/acg_shared_upstream.py match \\
    --base https://favip.fjapp.vip --upstream https://www.guopi.org \\
    --app-id 1291 --app-key KEY --case <案卷>
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
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT.parents[1]
OPS = _kit_ops_dir(Path(__file__))
DICTS = ROOT / "dicts"
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))

from scope_lib import host_of, in_scope, silent_expand  # noqa: E402

UA = "Mozilla/5.0 大爱仙尊-acg_shared_upstream"

# reuse one scraper/session for CF cookie jar (creating per-request is too slow)
_SCRAPER = None
_SCRAPER_FAILED = False


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def case_dir(case: str) -> Path:
    d = (ENGINE / "案卷" if (ENGINE / "案卷").is_dir() else ENGINE / "exports" / "bot-recovery") / case / "测绘" / "acg_shared"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _get_scraper():
    global _SCRAPER, _SCRAPER_FAILED
    if _SCRAPER_FAILED:
        return None
    if _SCRAPER is not None:
        return _SCRAPER
    try:
        import cloudscraper  # type: ignore

        _SCRAPER = cloudscraper.create_scraper()
        _SCRAPER.headers["User-Agent"] = UA
        return _SCRAPER
    except Exception:
        _SCRAPER_FAILED = True
        return None


def http(
    url: str,
    method: str = "GET",
    data: dict | None = None,
    timeout: int = 25,
) -> dict[str, Any]:
    hdrs = {
        "User-Agent": UA,
        "Accept": "application/json,text/html,*/*",
    }
    body = None
    if data is not None:
        body = urllib.parse.urlencode(data).encode()
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
            raw = r.read()[:2_000_000]
            return {
                "status": r.status,
                "body": raw.decode("utf-8", "replace"),
                "len": len(raw),
            }
    except urllib.error.HTTPError as e:
        raw = e.read()[:500_000] if e.fp else b""
        return {
            "status": e.code,
            "body": raw.decode("utf-8", "replace"),
            "len": len(raw),
        }
    except Exception as e:
        return {"status": 0, "error": str(e), "body": "", "len": 0}


def sign(params: dict[str, Any], app_key: str) -> str:
    d = {k: str(v) for k, v in params.items() if k != "sign" and str(v) != ""}
    q = urllib.parse.urlencode(sorted(d.items()))
    q = urllib.parse.unquote(q)
    return hashlib.md5((q + "&key=" + str(app_key)).encode()).hexdigest()


def shared_post(upstream: str, path: str, app_id: str, app_key: str, extra: dict | None = None) -> dict:
    upstream = upstream.rstrip("/")
    data: dict[str, Any] = {"app_id": str(app_id)}
    if extra:
        data.update(extra)
    data["sign"] = sign(data, app_key)
    # warm CF cookie jar per host via GET first
    _session_get(upstream + "/")
    return _session_post(upstream + path, data)


def ensure_scope(url: str, parent: str | None, case: str | None) -> None:
    h = host_of(url)
    if in_scope(h):
        return
    if parent and in_scope(host_of(parent)):
        silent_expand(
            parent=parent,
            discovered=[url if "://" in url else f"https://{h}"],
            case=case or "",
            note="acg_shared_upstream",
        )
        return
    raise SystemExit(f"[scope] {h} 不在授权范围，且无法从 parent 静默扩权")


def _session_get(url: str, timeout: int = 25) -> dict[str, Any]:
    """优先 cloudscraper（过 CF），失败回落 urllib。"""
    s = _get_scraper()
    if s is not None:
        try:
            r = s.get(url, timeout=timeout)
            return {"status": r.status_code, "body": r.text[:2_000_000], "len": len(r.content)}
        except Exception:
            pass
    return http(url, timeout=timeout)


def _session_post(url: str, data: dict, timeout: int = 30) -> dict[str, Any]:
    s = _get_scraper()
    if s is not None:
        try:
            r = s.post(url, data=data, timeout=timeout)
            out = {"status": r.status_code, "body": r.text[:2_000_000], "len": len(r.content)}
            try:
                out["json"] = r.json()
            except Exception:
                out["json"] = None
            return out
        except Exception:
            pass
    r = http(url, method="POST", data=data, timeout=timeout)
    try:
        r["json"] = json.loads(r.get("body") or "")
    except Exception:
        r["json"] = None
    return r


def _ingest_item(it: dict, cover_hosts: dict[str, int], details: list[dict], shared_hits: list[dict], cid: int | None = None) -> None:
    if not isinstance(it, dict):
        return
    cover = it.get("cover") or ""
    if isinstance(cover, str) and cover.startswith("http"):
        h = host_of(cover)
        cover_hosts[h] = cover_hosts.get(h, 0) + 1
    if it.get("shared_id"):
        shared_hits.append(
            {
                "id": it.get("id"),
                "name": it.get("name"),
                "shared_id": it.get("shared_id"),
                "category_probe": cid,
            }
        )
        # list endpoint sometimes already has shared_code
        if it.get("shared_code") or it.get("id") is not None:
            details.append(
                {
                    "id": it.get("id"),
                    "name": it.get("name"),
                    "shared_id": it.get("shared_id"),
                    "shared_code": it.get("shared_code"),
                    "cover": cover,
                    "price": it.get("price"),
                }
            )


def cmd_discover(args: argparse.Namespace) -> int:
    base = args.base.rstrip("/")
    ensure_scope(base, None, args.case)
    out = case_dir(args.case) if args.case else Path("/tmp/acg_shared")
    out.mkdir(parents=True, exist_ok=True)
    max_detail = max(1, int(args.max_detail))

    print(f"[discover] warm {base}/", flush=True)
    _session_get(base + "/")
    shared_hits: list[dict] = []
    cover_hosts: dict[str, int] = {}
    details: list[dict] = []
    seen_detail_ids: set[int] = set()

    # also scrape absolute cover hosts from homepage HTML
    home = _session_get(base + "/")
    for m in re.finditer(r"https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})[^\"'\s]*", home.get("body") or ""):
        h = m.group(1).lower()
        if h and h != host_of(base):
            cover_hosts[h] = cover_hosts.get(h, 0) + 1

    data_r = _session_get(base + "/user/api/index/data")
    print(f"[discover] index/data status={data_r.get('status')} len={data_r.get('len')}", flush=True)
    cat_ids: list[int] = []
    try:
        payload = json.loads(data_r.get("body") or "{}")
        rows = payload.get("data") or []
        if isinstance(rows, list):
            for row in rows:
                if isinstance(row, dict) and row.get("id") is not None:
                    cat_ids.append(int(row["id"]))
                if isinstance(row, dict) and isinstance(row.get("children"), list):
                    for ch in row["children"]:
                        if isinstance(ch, dict) and ch.get("id") is not None:
                            cat_ids.append(int(ch["id"]))
    except Exception:
        pass
    # prefer shared-heavy cats first; cap to keep CF sites usable
    seed = [3, 4, 5, 96, 100, 101, 102]
    cat_ids = list(dict.fromkeys(seed + sorted(set(cat_ids))))[:40]

    commodity_ids: list[int] = []
    for cid in cat_ids or [1, 2, 3, 4, 5]:
        for key in ("categoryId", "category_id"):
            r = _session_get(f"{base}/user/api/index/commodity?{key}={cid}&limit=50&page=1")
            try:
                arr = (json.loads(r.get("body") or "{}").get("data")) or []
            except Exception:
                arr = []
            if not isinstance(arr, list) or not arr:
                continue
            print(f"[discover] cat={cid} key={key} n={len(arr)}", flush=True)
            for it in arr:
                if not isinstance(it, dict):
                    continue
                if it.get("id") is not None:
                    commodity_ids.append(int(it["id"]))
                _ingest_item(it, cover_hosts, details, shared_hits, cid)
            break

    # only detail items that still lack shared_code (or none from list)
    need_detail = []
    have_code = {int(d["id"]) for d in details if d.get("id") is not None and d.get("shared_code")}
    for iid in sorted(set(commodity_ids)):
        if iid not in have_code:
            need_detail.append(iid)
    need_detail = need_detail[:max_detail]
    print(f"[discover] detail probes={len(need_detail)} (max={max_detail})", flush=True)

    for iid in need_detail:
        if iid in seen_detail_ids:
            continue
        seen_detail_ids.add(iid)
        r = _session_get(f"{base}/user/api/index/commodityDetail?commodityId={iid}")
        try:
            d = (json.loads(r.get("body") or "{}").get("data")) or {}
        except Exception:
            d = {}
        if not isinstance(d, dict):
            continue
        _ingest_item(d, cover_hosts, details, shared_hits)

    # dedupe details by (id, shared_code)
    uniq: dict[tuple, dict] = {}
    for d in details:
        key = (d.get("id"), d.get("shared_code"), d.get("shared_id"))
        if d.get("shared_id"):
            uniq[key] = d
    details = list(uniq.values())

    # suggest upstreams = external cover hosts (drop CDN/social noise)
    NOISE_SUFFIX = (
        "t.me",
        "telegram.org",
        "telegram.me",
        "qq.com",
        "cloudflareinsights.com",
        "cloudflare.com",
        "googleapis.com",
        "gstatic.com",
        "facebook.com",
        "twitter.com",
        "x.com",
        "youtube.com",
        "jsdelivr.net",
        "unpkg.com",
        "bootstrapcdn.com",
        "fontawesome.com",
    )
    base_host = host_of(base)
    suggestions = []
    for h, n in sorted(cover_hosts.items(), key=lambda x: -x[1]):
        if not h or h == base_host or h.endswith("." + base_host):
            continue
        if any(h == s or h.endswith("." + s) for s in NOISE_SUFFIX):
            continue
        suggestions.append({"host": h, "cover_count": n, "url": f"https://{h}"})

    # optional merchant dict overlap（优先正式文件，否则 example）
    merchants_path = Path(args.merchants) if args.merchants else DICTS / "shared_merchants.json"
    if not merchants_path.is_file():
        merchants_path = DICTS / "shared_merchants.example.json"
    known = []
    if merchants_path.is_file():
        try:
            known = json.loads(merchants_path.read_text(encoding="utf-8"))
        except Exception:
            known = []
    known_hits = []
    sug_hosts = {x["host"] for x in suggestions}
    for m in known if isinstance(known, list) else []:
        dh = host_of(m.get("domain") or "")
        if dh in sug_hosts or any(dh.endswith(s["host"]) for s in suggestions):
            known_hits.append(
                {
                    "name": m.get("name"),
                    "domain": m.get("domain"),
                    "app_id": m.get("app_id"),
                    "has_key": bool(m.get("app_key")),
                }
            )

    result = {
        "ts": _now(),
        "base": base,
        "shared_list_hits": len(shared_hits),
        "details": details,
        "cover_hosts": cover_hosts,
        "upstream_suggestions": suggestions,
        "known_merchant_hits": known_hits,
    }
    path = out / "discover.json"
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"[ok] details={len(details)} suggestions={len(suggestions)} -> {path}")
    for s in suggestions[:15]:
        print(f"  upstream? {s['url']}  covers={s['cover_count']}")
    for k in known_hits:
        print(f"  known_dict {k.get('domain')} app_id={k.get('app_id')} key={'yes' if k.get('has_key') else 'no'}")

    # silent expand suggestions if parent in scope
    if args.expand and suggestions:
        for s in suggestions:
            if not in_scope(s["host"]):
                try:
                    silent_expand(
                        parent=base,
                        discovered=[s["url"]],
                        case=args.case or "",
                        note="acg_shared discover cover",
                    )
                    print(f"  [expand] {s['host']}")
                except Exception as e:
                    print(f"  [expand-skip] {s['host']} {e}")
    return 0


def cmd_connect(args: argparse.Namespace) -> int:
    up = args.upstream.rstrip("/")
    ensure_scope(up, args.parent or args.base, args.case)
    out = case_dir(args.case) if args.case else Path("/tmp/acg_shared")
    r = shared_post(up, "/shared/authentication/connect", args.app_id, args.app_key)
    host = host_of(up).replace(".", "_")
    path = out / f"connect_{host}.json"
    path.write_text(json.dumps({"ts": _now(), "upstream": up, "resp": r}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    j = r.get("json") or {}
    print(f"[connect] status={r.get('status')} body={ (r.get('body') or '')[:240] }")
    print(f"[ok] -> {path}")
    if args.items:
        r2 = shared_post(up, "/shared/commodity/items", args.app_id, args.app_key)
        p2 = out / f"items_{host}.json"
        p2.write_text((r2.get("body") or "")[:5_000_000], encoding="utf-8")
        print(f"[items] status={r2.get('status')} len={r2.get('len')} -> {p2}")
    return 0 if (j.get("code") == 200 or (isinstance(j.get("data"), dict) and "balance" in (j.get("data") or {}))) else 2


def cmd_match(args: argparse.Namespace) -> int:
    base = args.base.rstrip("/")
    up = args.upstream.rstrip("/")
    ensure_scope(base, None, args.case)
    ensure_scope(up, base, args.case)
    out = case_dir(args.case) if args.case else Path("/tmp/acg_shared")

    # load discover or run lightweight detail list
    disc_path = out / "discover.json"
    codes: list[dict] = []
    if disc_path.is_file():
        disc = json.loads(disc_path.read_text(encoding="utf-8"))
        codes = disc.get("details") or []
    if not codes:
        print("[warn] no discover.json details; run discover first or pass --codes")
    if args.codes:
        for c in args.codes.split(","):
            c = c.strip()
            if c:
                codes.append({"shared_code": c, "name": "?"})

    matches = []
    for row in codes:
        code = row.get("shared_code")
        if not code:
            continue
        r = shared_post(
            up,
            "/shared/commodity/inventory",
            args.app_id,
            args.app_key,
            {"sharedCode": str(code)},
        )
        j = r.get("json") or {}
        data = j.get("data") if isinstance(j, dict) else None
        ok = isinstance(j, dict) and j.get("code") == 200 and isinstance(data, dict)
        matches.append(
            {
                "storefront_id": row.get("id"),
                "storefront_name": row.get("name"),
                "shared_id": row.get("shared_id"),
                "shared_code": code,
                "ok": ok,
                "count": (data or {}).get("count") if ok else None,
                "factory_price": (data or {}).get("factory_price") if ok else None,
                "price": (data or {}).get("price") if ok else None,
                "msg": None if ok else (j.get("msg") if isinstance(j, dict) else (r.get("body") or "")[:120]),
            }
        )
        flag = "HIT" if ok else "miss"
        print(f"  [{flag}] {code} {row.get('name','')[:30]} -> {matches[-1].get('count')} @{matches[-1].get('factory_price')}")

    conn = shared_post(up, "/shared/authentication/connect", args.app_id, args.app_key)
    chain = {
        "ts": _now(),
        "pattern": "acg-shared-upstream",
        "storefront": base,
        "upstream": up,
        "app_id": str(args.app_id),
        "connect": (conn.get("json") or conn.get("body")),
        "matches": matches,
        "hit_count": sum(1 for m in matches if m.get("ok")),
    }
    p1 = out / "match.json"
    p2 = out / "UPSTREAM_CHAIN.json"
    p1.write_text(json.dumps({"ts": _now(), "matches": matches}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    p2.write_text(json.dumps(chain, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"[ok] hits={chain['hit_count']}/{len(matches)} -> {p1}")
    print(f"[ok] chain -> {p2}")
    return 0


def cmd_inventory(args: argparse.Namespace) -> int:
    up = args.upstream.rstrip("/")
    ensure_scope(up, args.parent or args.base, args.case)
    out = case_dir(args.case) if args.case else Path("/tmp/acg_shared")
    r = shared_post(
        up,
        "/shared/commodity/inventory",
        args.app_id,
        args.app_key,
        {"sharedCode": args.code},
    )
    host = host_of(up).replace(".", "_")
    path = out / f"inventory_{host}_{args.code}.json"
    path.write_text(json.dumps({"ts": _now(), "resp": r}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print((r.get("body") or "")[:400])
    print(f"[ok] -> {path}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="ACG Shared 上游发现与对接")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("discover", help="橱窗枚举 shared_id/code + cover 宿主")
    p.add_argument("--base", required=True)
    p.add_argument("--case", required=True)
    p.add_argument("--merchants", default="", help="shared_merchants.json 路径")
    p.add_argument("--expand", action="store_true", help="cover 异 host 静默扩权")
    p.add_argument("--max-detail", type=int, default=40, help="commodityDetail 上限（默认 40）")
    p.set_defaults(func=cmd_discover)

    p = sub.add_parser("connect", help="Shared connect (+可选 items)")
    p.add_argument("--upstream", required=True)
    p.add_argument("--app-id", required=True)
    p.add_argument("--app-key", required=True)
    p.add_argument("--case", required=True)
    p.add_argument("--base", default="", help="橱窗 URL，用于静默扩权 parent")
    p.add_argument("--parent", default="")
    p.add_argument("--items", action="store_true")
    p.set_defaults(func=cmd_connect)

    p = sub.add_parser("match", help="橱窗 shared_code 对齐上游 inventory")
    p.add_argument("--base", required=True)
    p.add_argument("--upstream", required=True)
    p.add_argument("--app-id", required=True)
    p.add_argument("--app-key", required=True)
    p.add_argument("--case", required=True)
    p.add_argument("--codes", default="", help="逗号分隔额外 code")
    p.set_defaults(func=cmd_match)

    p = sub.add_parser("inventory", help="单 code 查库存")
    p.add_argument("--upstream", required=True)
    p.add_argument("--app-id", required=True)
    p.add_argument("--app-key", required=True)
    p.add_argument("--code", required=True)
    p.add_argument("--case", required=True)
    p.add_argument("--base", default="")
    p.add_argument("--parent", default="")
    p.set_defaults(func=cmd_inventory)

    args = ap.parse_args()
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
