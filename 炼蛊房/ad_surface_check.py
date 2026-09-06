#!/usr/bin/env python3
"""域/AD 表面检测（在已授权跳板或目标本机跑）。

只读：环境变量、krb5/sssd、监听端口、realm/klist 是否存在。
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import socket
import subprocess
import sys
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def _run(cmd: list[str], timeout: int = 6) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return ((r.stdout or "") + (r.stderr or "")).strip()[:2000]
    except Exception:
        return ""


def _port_open(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.4):
            return True
    except Exception:
        return False


def collect() -> dict[str, Any]:
    env_keys = (
        "USERDNSDOMAIN", "USERDOMAIN", "LOGONSERVER", "KRB5CCNAME",
        "KRB5_CONFIG", "REALM",
    )
    env = {k: os.environ.get(k, "") for k in env_keys if os.environ.get(k)}
    files = {}
    for p in (
        "/etc/krb5.conf",
        "/etc/sssd/sssd.conf",
        "/etc/samba/smb.conf",
        "/etc/resolv.conf",
    ):
        fp = Path(p)
        if fp.is_file() and os.access(fp, os.R_OK):
            try:
                txt = fp.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                txt = ""
            files[p] = {
                "readable": True,
                "has_realm": "realm" in txt.lower() or "[libdefaults]" in txt.lower(),
                "snippet": txt[:400].replace("\n", " "),
            }

    tools = {}
    for name in ("realm", "klist", "wbinfo", "net"):
        which = _run(["/usr/bin/which", name]) or _run(["which", name])
        tools[name] = which.splitlines()[0] if which else ""

    realm_list = _run(["realm", "list"]) if tools.get("realm") else ""
    klist = _run(["klist"]) if tools.get("klist") else ""
    hostname_d = _run(["hostname", "-d"])
    ports = {str(p): _port_open(p) for p in (88, 389, 445, 636, 3268, 3269)}

    is_domain = bool(
        env.get("USERDNSDOMAIN")
        or env.get("USERDOMAIN")
        or (files.get("/etc/krb5.conf") or {}).get("has_realm")
        or ("configured" in realm_list.lower() and realm_list)
        or any(ports[str(p)] for p in (88, 389, 3268))
    )

    next_cmds = [
        "python3 tools/tunnel-kit/internal_scan.py --help",
        "python3 炼蛊房/linux_lpe_checker.py --json --out 接管/lpe/lpe.json",
        "python3 炼蛊房/windows_lpe_checker.py --json --out 接管/lpe/windows_lpe.json",
    ]
    if is_domain:
        note = (
            "已像域成员/能看到 Kerberos 或 LDAP 口。"
            "下一步：隧道 + internal_scan；Windows 低权跑 windows_lpe_checker。"
            "BloodHound/Kerberoasting/DCSync 不在本库写步骤。"
        )
    else:
        note = "当前主机不像 AD 成员。打网站案退回 纵横天下.md，勿上 C2。"

    return {
        "os": platform.system(),
        "hostname": platform.node(),
        "is_domainish": is_domain,
        "env": env,
        "files": {k: {kk: vv for kk, vv in v.items() if kk != "snippet"} | {"snippet_len": len(v.get("snippet", ""))} for k, v in files.items()},
        "file_snippets_masked": {k: v.get("snippet", "")[:200] for k, v in files.items()},
        "tools": tools,
        "realm_list": realm_list[:500],
        "klist_present": bool(klist) and "No credentials" not in klist,
        "hostname_domain": hostname_d,
        "local_ports": ports,
        "note": note,
        "next": next_cmds,
        "playbook": "传承/宗门·认族.md",
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="域/AD 只读表面检测")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--case", default="")
    args = ap.parse_args()
    report = collect()
    report["ts"] = datetime.now(UTC).isoformat()
    text = json.dumps(report, ensure_ascii=False, indent=2)
    print(text)
    if args.case:
        d = ROOT / "案卷" / args.case / "测绘" / "ad"
        d.mkdir(parents=True, exist_ok=True)
        out_path = d / "surface.json"
    elif args.out:
        out_path = args.out
        out_path.parent.mkdir(parents=True, exist_ok=True)
    else:
        out_path = None
    if out_path is not None:
        out_path.write_text(text + "\n", encoding="utf-8")
        print(f"[+] wrote {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
