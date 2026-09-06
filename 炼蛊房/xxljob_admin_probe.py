#!/usr/bin/env python3
"""XXL-JOB 调度中心组合链 L1/L2（授权范围内）。

登录 + 执行器组/任务列表。不下发 GLUE、不调执行器 /run。
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, UTC
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

try:
    import requests
    requests.packages.urllib3.disable_warnings()  # type: ignore
except ImportError:
    print("[!] pip install requests", file=sys.stderr)
    sys.exit(1)

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import host_of, in_scope, write_probe_json  # noqa: E402

UA = "Mozilla/5.0 大爱仙尊-xxljob-admin"
CREDS = (("admin", "123456"),)


def _req(sess: requests.Session, method: str, url: str, **kw) -> requests.Response | None:
    kw.setdefault("timeout", 12)
    kw.setdefault("verify", False)
    try:
        return sess.request(method, url, **kw)
    except Exception:
        return None


def _has_login_cookie(r: requests.Response | None, sess: requests.Session) -> bool:
    if r is None:
        return False
    hdr = r.headers.get("Set-Cookie", "") or ""
    if "XXL_JOB_LOGIN_IDENTITY" in hdr:
        return True
    try:
        if r.cookies.get("XXL_JOB_LOGIN_IDENTITY") or sess.cookies.get("XXL_JOB_LOGIN_IDENTITY"):
            return True
    except Exception:
        pass
    return False


def _login_ok(r: requests.Response | None, sess: requests.Session) -> bool:
    if r is None:
        return False
    if _has_login_cookie(r, sess):
        return True
    loc = (r.headers.get("Location") or "").lower()
    if r.status_code in {301, 302, 303}:
        if "tologin" in loc:
            return False
        if loc.rstrip("/").endswith("index") or "/index?" in loc or "/index/" in loc:
            return True
    compact = (r.text or "").replace(" ", "")
    if '"code":200' in compact and "密码" not in (r.text or "") and "失败" not in (r.text or "")[:80]:
        return True
    return False


def run(args: argparse.Namespace) -> dict[str, Any]:
    host = host_of(args.base)
    if not host or not in_scope(host):
        print(f"[!] 不在 scope：{host or args.base}", file=sys.stderr)
        sys.exit(2)
    root = args.base.rstrip("/")
    prefixes = ["/xxl-job-admin", ""]
    sess = requests.Session()
    sess.verify = False
    sess.headers["User-Agent"] = UA
    findings: list[dict[str, Any]] = []
    prefix_hit = ""
    for pref in prefixes:
        for p in (f"{pref}/toLogin", f"{pref}/"):
            r = _req(sess, "GET", urljoin(root + "/", p.lstrip("/")), allow_redirects=True)
            if r is None:
                continue
            if "XXL-JOB" in r.text or "xxl-job-admin" in r.text or "分布式任务调度" in r.text:
                findings.append({"level": "L1", "signal": "admin-ui", "path": p, "status": r.status_code})
                print(f"  L1 admin-ui {p}")
                prefix_hit = pref
                break
        if prefix_hit or findings:
            break
    login_paths = []
    if prefix_hit:
        login_paths.append(f"{prefix_hit.rstrip('/')}/login")
    for extra in ("/xxl-job-admin/login", "/login"):
        if extra not in login_paths:
            login_paths.append(extra)
    logged = False
    login_path = login_paths[0]
    for cand in login_paths:
        for user, pw in CREDS:
            r = None
            for mode, hdrs, payload in (
                (
                    "data",
                    {"Content-Type": "application/x-www-form-urlencoded"},
                    {"userName": user, "password": pw},
                ),
                (
                    "json",
                    {"Content-Type": "application/json"},
                    {"userName": user, "password": pw},
                ),
            ):
                kw: dict[str, Any] = {"headers": hdrs, "allow_redirects": False}
                kw[mode] = payload
                r = _req(sess, "POST", urljoin(root + "/", cand.lstrip("/")), **kw)
                if _login_ok(r, sess):
                    break
            if _login_ok(r, sess):
                logged = True
                login_path = cand
                if cand.startswith("/xxl-job-admin"):
                    prefix_hit = "/xxl-job-admin"
                findings.append({
                    "level": "L2", "signal": "weak-login", "path": cand,
                    "user": user, "status": r.status_code if r else None,
                })
                print(f"  L2 weak-login {user} {cand}")
                break
        if logged:
            break
    if logged:
        for path, sig in (
            (f"{prefix_hit}/jobgroup/pageList", "jobgroup"),
            (f"{prefix_hit}/jobinfo/pageList", "jobinfo"),
        ):
            r = _req(
                sess, "POST", urljoin(root + "/", path.lstrip("/")),
                data={"start": "0", "length": "10"},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                allow_redirects=True,
            )
            if r is None:
                continue
            body = r.text[:4000]
            if any(k in body for k in ("jobGroup", "registryList", "triggerStatus", "recordsTotal")):
                findings.append({
                    "level": "L2", "signal": f"{sig}-list", "path": path,
                    "bytes": len(r.content or b""),
                    "note": "在线执行器/任务已列；GLUE add+trigger 先问",
                })
                print(f"  L2 {sig}-list")
    report = {
        "target": args.base,
        "ts": datetime.now(UTC).isoformat(),
        "findings": findings,
        "playbook": "传承/差事府·无门.md",
        "next": (
            "L2 有口+执行器列表后，GLUE_SHELL add/trigger 属 L3 先问；"
            "执行器 /run 仍先问。端口常见 9997/8080。"
        ),
    }
    out = write_probe_json(
        report, case=args.case, out=args.out,
        case_subdir="xxljob", filename="admin.json",
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"[+] wrote {out}", file=sys.stderr)
    return report


def cmd_doctor() -> int:
    src = Path(__file__).read_text(encoding="utf-8")
    checks = [
        "in_scope" in src,
        "glueSource" not in src.split("def cmd_doctor")[0],
        "/run" not in src or "不下发" in src,
        "XXL_JOB_LOGIN_IDENTITY" in src,
        "tologin" in src,
        (OPS.parent.parent / "传承/差事府·无门.md").is_file(),
    ]
    print(f"doctor {sum(checks)}/{len(checks)}")
    return 0 if all(checks) else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="XXL-JOB 调度中心 L1/L2（不 GLUE）")
    ap.add_argument("--base", "-u", default="")
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--doctor", action="store_true")
    args = ap.parse_args()
    if args.doctor:
        return cmd_doctor()
    if not args.base:
        ap.error("需要 --base")
    run(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
