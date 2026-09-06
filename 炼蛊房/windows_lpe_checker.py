#!/usr/bin/env python3
"""Windows 本地提权检测（授权主机上运行）。

在 macOS/Linux 上运行会提示「请拷到 Windows 目标执行」，并写出空报告。
不做内核 exploit，只收集 whoami/priv/服务/AlwaysInstallElevated 等配置面。
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def _run(cmd: list[str], timeout: int = 8) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=False)
        return (r.stdout or "") + (r.stderr or "")
    except Exception as e:
        return str(e)[:200]


def collect() -> dict[str, Any]:
    if os.name != "nt" and platform.system() != "Windows":
        return {
            "os": platform.system(),
            "skipped": True,
            "reason": "请在授权 Windows 目标上执行本脚本",
            "playbook": "传承/反客为主-窗府.md",
        }
    whoami = _run(["whoami"])
    priv = _run(["whoami", "/priv"])
    groups = _run(["whoami", "/groups"])
    sysinfo = _run(["systeminfo"])
    always = ""
    try:
        always = _run([
            "reg", "query",
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer",
            "/v", "AlwaysInstallElevated",
        ])
        always += _run([
            "reg", "query",
            r"HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer",
            "/v", "AlwaysInstallElevated",
        ])
    except Exception:
        pass
    se_imp = "SeImpersonatePrivilege" in priv and "Enabled" in priv
    findings = []
    if se_imp:
        findings.append({
            "level": "L2-hint",
            "signal": "SeImpersonate enabled",
            "note": "Potato 族方向；L3 先问。见 传承/反客为主-窗府.md",
        })
    if "0x1" in always or "0x00000001" in always:
        findings.append({
            "level": "L2",
            "signal": "AlwaysInstallElevated",
        })
    unquoted = _run([
        "powershell", "-NoProfile", "-Command",
        "Get-CimInstance Win32_Service | Where-Object { $_.PathName -and $_.PathName -notmatch '^\"' -and $_.PathName -match ' ' } | Select-Object -First 8 Name,PathName | Format-List | Out-String",
    ], timeout=20)
    if unquoted and "PathName" in unquoted:
        findings.append({
            "level": "L2-hint",
            "signal": "unquoted-service-path-suspect",
            "snippet": unquoted[:800],
        })
    return {
        "os": platform.platform(),
        "skipped": False,
        "whoami": whoami.strip()[:200],
        "priv_snippet": priv[:1500],
        "groups_snippet": groups[:800],
        "sysinfo_snippet": sysinfo[:800],
        "always_install_elevated": always[:400],
        "findings": findings,
        "playbook": "传承/反客为主-窗府.md",
        "cve_note": "内核面如 CVE-2026-68820 先对版本、先问再打",
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Windows LPE 配置检测")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--case", default="")
    args = ap.parse_args()
    report = collect()
    report["ts"] = datetime.now(UTC).isoformat()
    text = json.dumps(report, ensure_ascii=False, indent=2)
    print(text)
    if args.case:
        d = ROOT / "案卷" / args.case / "接管" / "lpe"
        d.mkdir(parents=True, exist_ok=True)
        out_path = d / "windows_lpe.json"
    elif args.out:
        out_path = args.out
        out_path.parent.mkdir(parents=True, exist_ok=True)
    else:
        out_path = None
    if out_path is not None:
        out_path.write_text(text, encoding="utf-8")
        print(f"[+] wrote {out_path}", file=sys.stderr)
    if report.get("skipped"):
        sys.exit(0)


if __name__ == "__main__":
    main()
