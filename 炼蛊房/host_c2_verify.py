#!/usr/bin/env python3
"""授权主机 C2 落地验证闸（L3）。

只做：scope 核对、案卷目录、verdict 记录。不生成 implant、不下载 C2 二进制。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, UTC
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))

from scope_lib import host_of, in_scope, safe_case_name  # noqa: E402

STACKS = ("sliver", "havoc", "other")
AV_ACTIONS = ("deleted", "quarantined", "allowed", "unknown")
CALLBACKS = ("yes", "no", "partial")
EDR_LABELS = (
    "unknown",
    "defender",
    "crowdstrike",
    "sentinelone",
    "carbonblack",
    "360",
    "huorong",
    "tencent",
    "other",
)


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _case_dir(case: str) -> Path:
    case = safe_case_name(case)
    if not case:
        raise SystemExit("[err] empty --case")
    d = ROOT / "案卷" / case / "测绘" / "host_c2"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _safe_host_tag(host: str) -> str:
    h = host_of(host) or host.strip()
    return re.sub(r"[^\w.\-]+", "_", h)[:120] or "host"


def _require_scope(host: str) -> str:
    h = host_of(host) or host.strip()
    if not h:
        raise SystemExit("[err] empty --host")
    if not in_scope(h):
        raise SystemExit(
            f"[err] host not in scope: {h}\n"
            "  → 先写入 config/scope_sites 并并入 company，再 init"
        )
    return h


def cmd_init(args: argparse.Namespace) -> int:
    host = _require_scope(args.host)
    if args.stack not in STACKS:
        raise SystemExit(f"[err] --stack must be one of {STACKS}")
    out = _case_dir(args.case)
    plan = {
        "ts": _now(),
        "case": args.case,
        "host": host,
        "os": args.os,
        "stack": args.stack,
        "edr": args.edr,
        "tier": "L3",
        "playbook": "传承/鬼不觉.md",
        "rules": [
            "implant/server binaries stay on attacker box; not committed to git",
            "listener bind lab/private IP only; no public C2 exposure",
            "record av_action + callback + session_id after test",
            "kill session and remove test payload unless RoE keeps evidence",
        ],
        "attacker_checklist": [
            "Install Sliver official release on attacker (not in this repo)",
            "Start server + mTLS/HTTP listener on lab IP",
            "Generate implant for --os; note sha256",
            "Copy to authorized host only; execute; watch AV + callback",
            "host_c2_verify.py record ...",
        ],
    }
    path = out / "plan.json"
    path.write_text(json.dumps(plan, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    summary = out / "SUMMARY.md"
    if not summary.is_file():
        summary.write_text(
            f"# host_c2 — {args.case}\n\n"
            f"- host: `{host}`\n"
            f"- stack: `{args.stack}` (L3)\n"
            f"- edr: `{args.edr}`\n"
            f"- status: **PLANNED** — await record\n"
            f"- playbook: `传承/鬼不觉.md`\n",
            encoding="utf-8",
        )
    print(json.dumps({"ok": True, "plan": str(path), "host": host}, ensure_ascii=False, indent=2))
    return 0


def cmd_record(args: argparse.Namespace) -> int:
    host = _require_scope(args.host)
    if args.av_action not in AV_ACTIONS:
        raise SystemExit(f"[err] --av-action must be one of {AV_ACTIONS}")
    if args.callback not in CALLBACKS:
        raise SystemExit(f"[err] --callback must be one of {CALLBACKS}")
    sha = (args.implant_sha256 or "").strip().lower()
    if sha and not re.fullmatch(r"[0-9a-f]{64}", sha):
        raise SystemExit("[err] --implant-sha256 must be 64 hex chars (or empty)")

    out = _case_dir(args.case)
    tag = _safe_host_tag(host)
    l3_pass = args.callback == "yes" and bool(args.session_id) and args.session_id != "none"
    verdict = {
        "ts": _now(),
        "case": args.case,
        "host": host,
        "os": args.os,
        "stack": args.stack,
        "edr": args.edr,
        "tier": "L3",
        "implant_sha256": sha or None,
        "av_action": args.av_action,
        "callback": args.callback,
        "session_id": args.session_id,
        "l3_pass": l3_pass,
        "note": (args.note or "").strip(),
        "interpretation": (
            "session_control_ok"
            if l3_pass
            else (
                "av_blocked_no_callback"
                if args.av_action in ("deleted", "quarantined") and args.callback == "no"
                else "incomplete"
            )
        ),
    }
    path = out / f"verdict_{tag}.json"
    path.write_text(json.dumps(verdict, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    lines = [
        f"# host_c2 — {args.case}",
        "",
        f"- host: `{host}`",
        f"- stack: `{args.stack}`",
        f"- edr: `{args.edr}`",
        f"- av_action: **{args.av_action}**",
        f"- callback: **{args.callback}**",
        f"- session_id: `{args.session_id}`",
        f"- L3 pass: **{'YES' if l3_pass else 'NO'}**",
        f"- interpretation: `{verdict['interpretation']}`",
    ]
    if sha:
        lines.append(f"- implant_sha256: `{sha}`")
    if args.note:
        lines.append(f"- note: {args.note.strip()}")
    lines.append("")
    (out / "SUMMARY.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"ok": True, "verdict": str(path), "l3_pass": l3_pass}, ensure_ascii=False, indent=2))
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    out = _case_dir(args.case)
    verdicts = sorted(out.glob("verdict_*.json"))
    if not verdicts:
        msg = f"[err] no verdict_*.json under {out}"
        if args.strict:
            raise SystemExit(msg)
        print(msg)
        return 1
    rows = []
    for p in verdicts:
        rows.append(json.loads(p.read_text(encoding="utf-8")))
    any_pass = any(r.get("l3_pass") for r in rows)
    report = {
        "case": args.case,
        "count": len(rows),
        "any_l3_pass": any_pass,
        "hosts": [
            {
                "host": r.get("host"),
                "l3_pass": r.get("l3_pass"),
                "av_action": r.get("av_action"),
                "edr": r.get("edr"),
                "callback": r.get("callback"),
            }
            for r in rows
        ],
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if args.strict and not any_pass:
        raise SystemExit("[err] strict: no host reached L3 pass (callback=yes + session_id)")
    return 0


def cmd_doctor(_args: argparse.Namespace) -> int:
    """只检查攻击机 PATH，不下载、不生成 implant。"""
    import shutil

    names = ("sliver", "sliver-server", "sliver-client")
    found = {n: (shutil.which(n) or "") for n in names}
    report = {
        "ok": any(found.values()),
        "found": {k: v or None for k, v in found.items()},
        "note": "官方 release 装在攻击机；二进制不进本仓库。没有则按 Bishop Fox 文档自备。",
        "next": "python3 炼蛊房/host_c2_verify.py init --case <案卷> --host <授权主机> --edr unknown",
        "playbook": "传承/鬼不觉.md",
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["ok"] else 1


def main() -> None:
    ap = argparse.ArgumentParser(description="授权主机 C2 L3 验证闸")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init", help="scope 闸 + 写 plan.json")
    p_init.add_argument("--case", required=True)
    p_init.add_argument("--host", required=True)
    p_init.add_argument("--os", default="windows", choices=("windows", "linux", "darwin"))
    p_init.add_argument("--stack", default="sliver", choices=STACKS)
    p_init.add_argument("--edr", default="unknown", choices=EDR_LABELS)
    p_init.set_defaults(func=cmd_init)

    p_rec = sub.add_parser("record", help="记录 AV/回连/会话结果")
    p_rec.add_argument("--case", required=True)
    p_rec.add_argument("--host", required=True)
    p_rec.add_argument("--os", default="windows", choices=("windows", "linux", "darwin"))
    p_rec.add_argument("--stack", default="sliver", choices=STACKS)
    p_rec.add_argument("--edr", default="unknown", choices=EDR_LABELS)
    p_rec.add_argument("--implant-sha256", default="")
    p_rec.add_argument("--av-action", required=True, choices=AV_ACTIONS)
    p_rec.add_argument("--callback", required=True, choices=CALLBACKS)
    p_rec.add_argument("--session-id", required=True)
    p_rec.add_argument("--note", default="")
    p_rec.set_defaults(func=cmd_record)

    p_chk = sub.add_parser("check", help="核对是否已有 L3 通过记录")
    p_chk.add_argument("--case", required=True)
    p_chk.add_argument("--strict", action="store_true")
    p_chk.set_defaults(func=cmd_check)

    p_doc = sub.add_parser("doctor", help="检查攻击机是否有官方 Sliver（不下载）")
    p_doc.set_defaults(func=cmd_doctor)

    args = ap.parse_args()
    raise SystemExit(args.func(args))


if __name__ == "__main__":
    main()
