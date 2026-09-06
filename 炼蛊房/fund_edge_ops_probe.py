#!/usr/bin/env python3
"""会员资金面边缘越权探针（授权内，默认只读）。

对齐 Playbook：传承/血神子·账.md
Skill：杀招/血神子·锋

子命令:
  doctor       本地自检（不打网）
  harvest      玩家票打 init/turnWater/task-center/tenant
  wallet-swap  A 票 + B wallet_id（query/body/header）
  dual-path    同一 token 打两条 path，比鉴权
  display-addr 两条路/两个号的收款址对照
  message-oracle 消息/工单换键
  saga-read    提现列表/流水只读；有 fundsn 则对照
  cors         Origin 反射 + credentials
  matrix       上面几项打包（至少 A 票）

示例:
  python3 炼蛊房/fund_edge_ops_probe.py doctor
  python3 炼蛊房/fund_edge_ops_probe.py matrix \\
    --base https://授权站 --case <案卷> \\
    --token-a "$A" --token-b "$B" --wallet-b "$WB" \\
    --prefix /prod-api --cookie 'sid=…'
"""
from __future__ import annotations

import argparse
import json
import re
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, UTC
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urljoin, urlparse

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))

from scope_lib import host_of, in_scope, write_probe_json  # noqa: E402

UA = "Mozilla/5.0 大爱仙尊-fund-edge-ops"
ADDR_KEYS = (
    "address", "depositaddress", "rechargeaddress", "walletaddress",
    "usdtaddress", "recvaddress", "receiveaddress", "payaddress",
    "toaddress", "chainaddress",
)
WALLET_KEYS = ("wallet_id", "walletId", "fund_id", "fundId")
HARVEST_PATHS = (
    "/api/init", "/api/init2", "/init2",
    "/api/turnWaterInit", "/turnWaterInit", "/api/water/init",
    "/api/task-center", "/api/task/center", "/api/taskCenter",
    "/api/config", "/api/site/config", "/api/tenant/config",
    "/api/public/config", "/api/app-config",
)
MESSAGE_PATHS = (
    "/api/message/list", "/api/notice/list", "/api/inbox",
    "/api/ticket/list", "/api/cs/ticket", "/api/im/history",
    "/api/notify/list", "/api/msg/list",
)
SAGA_PATHS = (
    "/api/withdraw/list", "/api/withdraw/detail", "/api/withdrawal/list",
    "/api/fund/record", "/api/payout/list", "/api/cashout/list",
)
WALLET_PATHS = (
    "/api/wallet/address", "/api/wallet/info", "/api/fund/address",
    "/api/deposit/address", "/api/recharge/address", "/api/pay/address",
)
DUAL_PAIRS = (
    ("/api/wallet/address", "/api/fund/address"),
    ("/api/wallet/info", "/api/finance/wallet"),
    ("/api/deposit/address", "/api/pay/address"),
    ("/api/withdraw/list", "/api/fund/record"),
)
HOST_RE = re.compile(r"https?://([a-z0-9.-]+\.[a-z]{2,})(?::\d+)?", re.I)
ID_KEYS = frozenset({
    "siteid", "site_id", "tenantid", "tenant_id", "merchantid", "merchant_id",
    "agentid", "agent_id",
})
PLACES = ("query", "body", "header")



def _ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def ensure_scope(url: str) -> None:
    h = host_of(url)
    if h in ("127.0.0.1", "localhost", "::1"):
        return
    if not in_scope(h):
        raise SystemExit(f"[scope] refuse out-of-scope host: {h}")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """禁止跟随跳转，避免 Bearer 落到 scope 外 host。"""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def _opener() -> urllib.request.OpenerDirector:
    ctx = ssl._create_unverified_context()
    return urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx),
        _NoRedirect(),
    )


def _parse_header_args(items: list[str] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in items or []:
        k, _, v = item.partition(":")
        if k.strip():
            out[k.strip()] = v.strip()
    return out


def _pref(prefix: str, path: str) -> str:
    p = path if path.startswith("/") else "/" + path
    pre = (prefix or "").strip()
    if not pre:
        return p
    if not pre.startswith("/"):
        pre = "/" + pre
    pre = pre.rstrip("/")
    if p == pre or p.startswith(pre + "/"):
        return p
    return pre + p


def _http(
    method: str,
    url: str,
    *,
    token: str | None = None,
    body: dict[str, Any] | None = None,
    extra_headers: dict[str, str] | None = None,
    cookie: str = "",
    timeout: float = 20.0,
) -> dict[str, Any]:
    headers = {"User-Agent": UA, "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
        headers["token"] = token
    if cookie:
        headers["Cookie"] = cookie
    if extra_headers:
        headers.update(extra_headers)
    data = None
    if body is not None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method.upper())
    try:
        with _opener().open(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            hdrs = {k.lower(): v for k, v in dict(resp.headers.items()).items()}
            return {"status": resp.status, "text": raw, "size": len(raw), "error": "", "headers": hdrs}
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace") if e.fp else ""
        hdrs = {k.lower(): v for k, v in dict(e.headers.items() if e.headers else {}).items()}
        return {"status": e.code, "text": raw, "size": len(raw), "error": "", "headers": hdrs}
    except Exception as e:
        return {"status": 0, "text": "", "size": 0, "error": str(e)[:160], "headers": {}}


def _snip(text: str, n: int = 160) -> str:
    return re.sub(r"\s+", " ", text or "")[:n]


def _json_or_none(text: str) -> Any:
    try:
        return json.loads(text)
    except Exception:
        return None


def _walk_strings(obj: Any, pred) -> list[str]:
    out: list[str] = []

    def rec(x: Any, key: str = "") -> None:
        if isinstance(x, dict):
            for k, v in x.items():
                rec(v, str(k))
        elif isinstance(x, list):
            for i in x[:30]:
                rec(i, key)
        elif isinstance(x, (str, int, float)) and pred(key, x):
            out.append(str(x))

    rec(obj)
    return out[:20]


def _extract_addrs(text: str) -> list[str]:
    data = _json_or_none(text)
    if data is None:
        return []

    def pred(k: str, v: Any) -> bool:
        if k.lower().replace("_", "") not in ADDR_KEYS:
            return False
        s = str(v)
        return 8 <= len(s) <= 128 and s.lower() not in {"null", "none", ""}

    return list(dict.fromkeys(_walk_strings(data, pred)))


def _extract_hosts(text: str) -> list[str]:
    return list(dict.fromkeys(m.group(1).lower() for m in HOST_RE.finditer(text or "")))[:16]


def _extract_ids(text: str) -> list[str]:
    data = _json_or_none(text)
    if data is None:
        return []

    def pred(k: str, v: Any) -> bool:
        return k.lower() in ID_KEYS and str(v).strip() not in {"", "0", "null"}

    return list(dict.fromkeys(_walk_strings(data, pred)))[:12]


def _looks_config(text: str) -> bool:
    data = _json_or_none(text)
    if not isinstance(data, (dict, list)):
        return False
    keys = ("siteid", "tenant", "domain", "houtai", "admin", "turnwater", "taskcenter")
    low = (text or "").lower()
    return any(k in low for k in keys) and len(text) >= 80


def grade_dual_path(status_a: int, status_b: int, addrs_a: list[str], addrs_b: list[str]) -> str | None:
    """200 vs 404 不算；200 vs 401/403 才是 L1；两边 200 且地址都有且不同才 L2。"""
    both_ok = status_a == 200 and status_b == 200
    addr_diff = bool(addrs_a) and bool(addrs_b) and addrs_a != addrs_b
    if both_ok and addr_diff:
        return "L2"
    if {status_a, status_b} <= {200, 401, 403} and 200 in {status_a, status_b} and status_a != status_b:
        return "L1"
    return None


def grade_display_hijack(own_a: list[str], own_b: list[str], leaked: list[str]) -> str | None:
    """共享平台收款址（A==B）不算展示层劫持；必须是换键后读到 B 且不同于 A。"""
    if not leaked or not own_b:
        return None
    if set(leaked) & set(own_b) and set(leaked) != set(own_a or []):
        return "L2"
    return None


def grade_wallet_swap(own_status: int, swap_status: int, own_addrs: list[str], swap_addrs: list[str]) -> str | None:
    if swap_status != 200 or own_status not in {200, 401, 403}:
        return None
    if swap_addrs and swap_addrs != own_addrs:
        return "L2"
    if own_status in {401, 403} and swap_status == 200:
        return "L1"
    return None


def grade_cors(acao: str, acac: str, origin: str) -> str | None:
    acao_l = (acao or "").strip()
    acac_l = (acac or "").strip().lower()
    if acao_l == "*":
        return "L1"
    if acao_l == origin and acac_l == "true":
        return "L1"
    return None


def _join(base: str, path: str) -> str:
    return urljoin(base.rstrip("/") + "/", path.lstrip("/"))


def _places(spec: str) -> list[str]:
    raw = [x.strip() for x in (spec or "query,body,header").split(",") if x.strip()]
    out = [x for x in raw if x in PLACES]
    return out or ["query"]


def _annotate(row: dict[str, Any], path: str, url: str) -> dict[str, Any]:
    row["url"] = url
    row["path"] = path
    row["addrs"] = _extract_addrs(row.get("text") or "")
    row["hosts"] = _extract_hosts(row.get("text") or "")
    row["ids"] = _extract_ids(row.get("text") or "")
    row["snip"] = _snip(row.get("text") or "")
    return row


def _call(
    args: argparse.Namespace,
    path: str,
    token: str,
    *,
    query: dict[str, str] | None = None,
    body: dict[str, Any] | None = None,
    extra_headers: dict[str, str] | None = None,
    method: str = "GET",
) -> dict[str, Any]:
    url = _join(args.base, _pref(getattr(args, "prefix", "") or "", path))
    if query:
        url = url + ("&" if "?" in url else "?") + urlencode(query)
    hdrs = _parse_header_args(getattr(args, "header", None))
    if extra_headers:
        hdrs.update(extra_headers)
    row = _http(
        method, url, token=token, body=body,
        extra_headers=hdrs or None,
        cookie=getattr(args, "cookie", "") or "",
    )
    return _annotate(row, path, url)


def _wallet_header_name(key: str) -> str:
    if key.lower() in {"wallet_id", "walletid"}:
        return "X-Wallet-Id"
    if key.lower() in {"fund_id", "fundid"}:
        return "X-Fund-Id"
    return "X-" + key.replace("_", "-")


def cmd_doctor(_args: argparse.Namespace) -> dict[str, Any]:
    checks = [
        grade_dual_path(200, 404, ["Txxx12345678"], []) is None,
        grade_dual_path(200, 403, [], []) == "L1",
        grade_dual_path(200, 200, ["Aaa11111111"], ["Bbb22222222"]) == "L2",
        grade_display_hijack(["Shared1111"], ["Shared1111"], ["Shared1111"]) is None,
        grade_display_hijack(["AddrA11111"], ["AddrB22222"], ["AddrB22222"]) == "L2",
        grade_wallet_swap(403, 200, [], []) == "L1",
        grade_cors("*", "false", "https://a.example") == "L1",
        grade_cors("https://t.example", "true", "https://t.example") == "L1",
        grade_cors("https://t.example", "false", "https://evil.example") is None,
        _pref("/prod-api", "/api/init") == "/prod-api/api/init",
        _pref("/api", "/api/init") == "/api/init",
    ]
    ok = all(checks)
    print(f"  doctor {'ok' if ok else 'FAIL'} checks={len(checks)}")
    return {"cmd": "doctor", "findings": [], "ok": ok, "checks": len(checks)}


def cmd_harvest(args: argparse.Namespace) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    for p in HARVEST_PATHS:
        row = _call(args, p, args.token)
        if row["error"] or row["status"] in {0, 404, 405, 502, 503}:
            continue
        if row["status"] != 200 or _json_or_none(row["text"]) is None:
            continue
        interesting = _looks_config(row["text"]) or bool(row["addrs"]) or bool(row["hosts"]) or bool(row["ids"])
        if interesting:
            findings.append({
                "level": "L1",
                "signal": "player-token-harvest",
                "path": p,
                "status": row["status"],
                "size": row["size"],
                "addrs": row["addrs"][:5],
                "hosts": row["hosts"][:8],
                "ids": row["ids"][:8],
                "snip": row["snip"],
            })
            print(f"  L1 harvest {p} {row['status']} size={row['size']} hosts={row['hosts'][:3]}")
    return {"cmd": "harvest", "findings": findings}


def cmd_wallet_swap(args: argparse.Namespace) -> dict[str, Any]:
    paths = [args.path] if args.path else list(WALLET_PATHS)
    findings: list[dict[str, Any]] = []
    for p in paths:
        own = _call(args, p, args.token_a)
        if own["error"] or own["status"] in {0, 404, 405}:
            continue
        hit = False
        for key in WALLET_KEYS:
            for place in _places(getattr(args, "place", "") or ""):
                if place == "query":
                    swapped = _call(args, p, args.token_a, query={key: args.wallet_b})
                elif place == "body":
                    swapped = _call(args, p, args.token_a, body={key: args.wallet_b}, method="POST")
                else:
                    swapped = _call(
                        args, p, args.token_a,
                        extra_headers={_wallet_header_name(key): args.wallet_b},
                    )
                if swapped["error"]:
                    continue
                level = grade_wallet_swap(
                    own["status"], swapped["status"], own["addrs"], swapped["addrs"],
                )
                if level:
                    findings.append({
                        "level": level,
                        "signal": "wallet-id-swap",
                        "path": p,
                        "param": key,
                        "place": place,
                        "own_status": own["status"],
                        "swap_status": swapped["status"],
                        "own_addrs": own["addrs"][:3],
                        "swap_addrs": swapped["addrs"][:3],
                        "snip": swapped["snip"],
                    })
                    print(f"  {level} wallet-swap {p} {key} @{place}")
                    hit = True
                    break
            if hit:
                break
    return {"cmd": "wallet-swap", "findings": findings}


def cmd_dual_path(args: argparse.Namespace) -> dict[str, Any]:
    a = _call(args, args.path_a, args.token)
    b = _call(args, args.path_b, args.token)
    findings: list[dict[str, Any]] = []
    if a["error"] and b["error"]:
        return {"cmd": "dual-path", "findings": findings, "a": a, "b": b}
    level = grade_dual_path(a["status"], b["status"], a["addrs"], b["addrs"])
    if level:
        findings.append({
            "level": level,
            "signal": "dual-path",
            "path_a": args.path_a,
            "path_b": args.path_b,
            "status_a": a["status"],
            "status_b": b["status"],
            "addrs_a": a["addrs"][:3],
            "addrs_b": b["addrs"][:3],
            "snip_a": a["snip"],
            "snip_b": b["snip"],
        })
        print(f"  {level} dual-path {args.path_a}={a['status']} vs {args.path_b}={b['status']}")
    return {"cmd": "dual-path", "findings": findings}


def cmd_display_addr(args: argparse.Namespace) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    path_a = args.path_a or "/api/wallet/address"
    path_b = args.path_b or "/api/init2"
    a = _call(args, path_a, args.token_a)
    b = _call(args, path_b, args.token_a)
    if a["addrs"] and b["addrs"] and a["addrs"] != b["addrs"]:
        findings.append({
            "level": "L1",
            "signal": "display-vs-assign",
            "path_a": path_a,
            "path_b": path_b,
            "addrs_a": a["addrs"][:3],
            "addrs_b": b["addrs"][:3],
        })
        print(f"  L1 display-addr mismatch {path_a} vs {path_b}")
    if args.token_b and args.wallet_b:
        other = _call(args, path_a, args.token_b)
        leaked = _call(args, path_a, args.token_a, query={"wallet_id": args.wallet_b})
        level = grade_display_hijack(a["addrs"], other["addrs"], leaked["addrs"])
        if level:
            findings.append({
                "level": level,
                "signal": "display-hijack-read-other",
                "path": path_a,
                "own_a": a["addrs"][:3],
                "leaked": leaked["addrs"][:3],
                "other": other["addrs"][:3],
            })
            print(f"  {level} display-addr A-ticket read B address")
    return {"cmd": "display-addr", "findings": findings}


def cmd_message_oracle(args: argparse.Namespace) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    extra: dict[str, str] = {}
    if args.wallet_b:
        extra["wallet_id"] = args.wallet_b
    if args.order_id:
        extra["order_id"] = args.order_id
    for p in MESSAGE_PATHS:
        base_row = _call(args, p, args.token)
        if base_row["error"] or base_row["status"] not in {200, 201}:
            continue
        if _json_or_none(base_row["text"]) is None:
            continue
        if extra:
            row = _call(args, p, args.token, query=extra)
            if row["error"] or _json_or_none(row.get("text") or "") is None:
                continue
            changed = (
                row["addrs"] and row["addrs"] != base_row["addrs"]
            ) or abs(row["size"] - base_row["size"]) >= 80
            if not changed:
                continue
            findings.append({
                "level": "L2" if row["addrs"] and row["addrs"] != base_row["addrs"] else "L1",
                "signal": "message-oracle-swap",
                "path": p,
                "status": row["status"],
                "size": row["size"],
                "addrs": row["addrs"][:3],
                "snip": row["snip"],
            })
            print(f"  {findings[-1]['level']} message-oracle {p} size={row['size']}")
            continue
        if base_row["addrs"]:
            findings.append({
                "level": "L1",
                "signal": "message-oracle-addr",
                "path": p,
                "status": base_row["status"],
                "size": base_row["size"],
                "addrs": base_row["addrs"][:3],
                "snip": base_row["snip"],
            })
            print(f"  L1 message-oracle {p} size={base_row['size']}")
    return {"cmd": "message-oracle", "findings": findings}


def cmd_saga_read(args: argparse.Namespace) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    for p in SAGA_PATHS:
        row = _call(args, p, args.token)
        if row["error"] or row["status"] in {0, 404, 405}:
            continue
        data = _json_or_none(row["text"])
        if row["status"] != 200 or data is None:
            continue
        blob = (row["text"] or "").lower()
        if "fundsn" not in blob and "withdraw" not in blob and not row["addrs"]:
            continue
        item = {
            "level": "L1",
            "signal": "saga-read",
            "path": p,
            "status": row["status"],
            "size": row["size"],
            "snip": row["snip"],
        }
        if args.fundsn:
            swapped = _call(args, p, args.token, query={"fundsn": args.fundsn})
            if (
                not swapped["error"]
                and swapped["status"] == 200
                and _json_or_none(swapped["text"]) is not None
                and (
                    (swapped["addrs"] and swapped["addrs"] != row["addrs"])
                    or abs(swapped["size"] - row["size"]) >= 80
                )
            ):
                item["level"] = "L2" if swapped["addrs"] and swapped["addrs"] != row["addrs"] else "L1"
                item["signal"] = "saga-fundsn-swap"
                item["swap_size"] = swapped["size"]
                item["swap_addrs"] = swapped["addrs"][:3]
        findings.append(item)
        print(f"  {item['level']} saga-read {p} {row['status']}")
    return {"cmd": "saga-read", "findings": findings, "note": "只读；不对他人单 POST 完成/打款"}


def cmd_cors(args: argparse.Namespace) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    path = args.path or "/api/wallet/address"
    parsed = urlparse(args.base)
    origin = args.origin or f"{parsed.scheme}://tenant.{parsed.netloc}"
    row = _call(
        args, path, args.token or args.token_a,
        extra_headers={"Origin": origin},
        method="OPTIONS",
    )
    if row["error"] and row["status"] == 0:
        row = _call(
            args, path, args.token or args.token_a,
            extra_headers={"Origin": origin},
        )
    acao = (row.get("headers") or {}).get("access-control-allow-origin", "")
    acac = (row.get("headers") or {}).get("access-control-allow-credentials", "")
    level = grade_cors(acao, acac, origin)
    if level:
        findings.append({
            "level": level,
            "signal": "cors-reflect",
            "path": path,
            "origin": origin,
            "acao": acao,
            "acac": acac,
            "status": row["status"],
        })
        print(f"  {level} cors {path} ACAO={acao} ACAC={acac}")
    return {"cmd": "cors", "findings": findings, "origin": origin, "next": "细测交 core-web-vuln-kit；证据挂本卡"}


def cmd_matrix(args: argparse.Namespace) -> dict[str, Any]:
    chunks: list[dict[str, Any]] = []
    args.token = args.token_a
    chunks.append(cmd_harvest(args))
    chunks.append(cmd_display_addr(args))
    if args.wallet_b:
        chunks.append(cmd_wallet_swap(args))
    chunks.append(cmd_message_oracle(args))
    chunks.append(cmd_saga_read(args))
    chunks.append(cmd_cors(args))
    if args.path_a and args.path_b:
        pairs = [(args.path_a, args.path_b)]
    else:
        pairs = list(DUAL_PAIRS)
    for pa, pb in pairs:
        args.path_a, args.path_b = pa, pb
        chunks.append(cmd_dual_path(args))
    findings = [f for c in chunks for f in c.get("findings") or []]
    return {"cmd": "matrix", "chunks": [c["cmd"] for c in chunks], "findings": findings}


def _level_of(findings: list[dict[str, Any]]) -> str:
    if any(f.get("level") == "L2" for f in findings):
        return "L2"
    if findings:
        return "L1"
    return "none"


def main() -> None:
    ap = argparse.ArgumentParser(description="会员资金面边缘越权（授权内，默认只读）")
    ap.add_argument("cmd", choices=(
        "doctor", "harvest", "wallet-swap", "dual-path", "display-addr",
        "message-oracle", "saga-read", "cors", "matrix",
    ))
    ap.add_argument("--base", default="")
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--token", default="")
    ap.add_argument("--token-a", default="")
    ap.add_argument("--token-b", default="")
    ap.add_argument("--wallet-b", default="")
    ap.add_argument("--order-id", default="")
    ap.add_argument("--fundsn", default="")
    ap.add_argument("--path", default="")
    ap.add_argument("--path-a", default="")
    ap.add_argument("--path-b", default="")
    ap.add_argument("--prefix", default="", help="网关前缀，如 /prod-api")
    ap.add_argument("--cookie", default="")
    ap.add_argument("--header", action="append", default=[], help="额外头，可重复：X-Token:…")
    ap.add_argument("--place", default="query,body,header", help="wallet 参数位置")
    ap.add_argument("--origin", default="", help="CORS 探测用 Origin")
    args = ap.parse_args()

    if args.cmd != "doctor":
        if not args.base:
            raise SystemExit("[!] 需要 --base")
        ensure_scope(args.base)

    if args.cmd in {"harvest", "message-oracle", "saga-read", "cors"} and not args.token:
        args.token = args.token_a
    if args.cmd in {"harvest", "message-oracle", "saga-read"} and not args.token:
        raise SystemExit(f"[!] {args.cmd} 需要 --token 或 --token-a")
    if args.cmd == "cors" and not args.token:
        raise SystemExit("[!] cors 需要 --token 或 --token-a")
    if args.cmd == "dual-path":
        args.token = args.token or args.token_a
        if not args.token or not args.path_a or not args.path_b:
            raise SystemExit("[!] dual-path 需要 --token --path-a --path-b")
    if args.cmd == "wallet-swap":
        if not args.token_a or not args.wallet_b:
            raise SystemExit("[!] wallet-swap 需要 --token-a --wallet-b")
    if args.cmd == "display-addr":
        args.token_a = args.token_a or args.token
        if not args.token_a:
            raise SystemExit("[!] display-addr 需要 --token-a")
    if args.cmd == "matrix":
        if not args.token_a:
            raise SystemExit("[!] matrix 需要 --token-a（有 B 票再加 --token-b --wallet-b）")

    handlers = {
        "doctor": cmd_doctor,
        "harvest": cmd_harvest,
        "wallet-swap": cmd_wallet_swap,
        "dual-path": cmd_dual_path,
        "display-addr": cmd_display_addr,
        "message-oracle": cmd_message_oracle,
        "saga-read": cmd_saga_read,
        "cors": cmd_cors,
        "matrix": cmd_matrix,
    }
    body = handlers[args.cmd](args)
    findings = body.get("findings") or []
    report = {
        "target": (args.base or "").rstrip("/"),
        "ts": _now(),
        "cmd": args.cmd,
        "level": _level_of(findings) if args.cmd != "doctor" else ("ok" if body.get("ok") else "fail"),
        **body,
        "playbook": "传承/血神子·账.md",
        "next": "L2=A票读到B资金对象或展示址被换。回对象矩阵；真提现/改他人址先问。",
    }
    if args.cmd == "doctor":
        print(json.dumps({"ok": body.get("ok"), "checks": body.get("checks")}, ensure_ascii=False))
        if not body.get("ok"):
            raise SystemExit(1)
        return
    out_path = write_probe_json(
        report, case=args.case, out=args.out,
        case_subdir="fund_edge", filename="latest.json",
    )
    print(json.dumps(
        {"level": report["level"], "findings": len(findings), "out": str(out_path)},
        ensure_ascii=False,
    ))


if __name__ == "__main__":
    main()
