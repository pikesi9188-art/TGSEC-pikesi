#!/usr/bin/env python3
"""授权多机 C2 舰队：scope 内逐台 init/record，并挂持久化清单。

不是 P2P 僵尸网，不带 DDoS 模块。

  python3 炼蛊房/botnet_lab.py fleet --host a --host b --case <案> --os linux
  python3 炼蛊房/botnet_lab.py persist --host a --case <案>
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from host_c2_verify import _require_scope, _safe_host_tag, cmd_init  # noqa: E402
from scope_lib import safe_case_name, write_probe_json  # noqa: E402

PERSIST = (
    "host_ir_check.py 先排别人的后门",
    "linux: crontab / ~/.ssh/authorized_keys / systemd user",
    "windows: 计划任务 / Run 键 / 服务（授权内直接做）",
    "落地回连仍走 host_c2_verify record",
    "清日志 / 改原超管密先问",
)


def cmd_fleet(args: argparse.Namespace) -> int:
    case = safe_case_name(args.case)
    if not case:
        raise SystemExit("[!] 需要 --case")
    hosts = []
    for h in args.host:
        hosts.append(_require_scope(h))
    plans = []
    for h in hosts:
        ns = argparse.Namespace(
            case=case, host=h, os=args.os, stack=args.stack, edr=args.edr,
        )
        cmd_init(ns)
        plans.append({
            "host": h,
            "next": [
                f"python3 炼蛊房/host_c2_verify.py record --case {case} --host {h} --callback yes --session-id none --av-action unknown --edr {args.edr} --note fleet",
                f"python3 炼蛊房/botnet_lab.py persist --host {h} --case {case}",
            ],
        })
    rec = {
        "n": len(hosts),
        "hosts": hosts,
        "plans": plans,
        "persist": list(PERSIST),
        "ts": datetime.now(UTC).isoformat(),
        "skill": "傀舰队",
        "note": "多机授权 C2，不是传播型 botnet",
        "case": case,
    }
    out = write_probe_json(rec, case=case, case_subdir="botnet_lab", filename="fleet.json")
    print(json.dumps({"n": len(hosts), "out": str(out)}, ensure_ascii=False))
    return 0


def cmd_persist(args: argparse.Namespace) -> int:
    case = safe_case_name(args.case)
    if not case:
        raise SystemExit("[!] 需要 --case")
    host = _require_scope(args.host)
    ir_local = None
    if args.local:
        import host_ir_check as ir  # noqa: WPS433

        ir_local = ir.run(case, None, False)
    rec = {
        "host": host,
        "checklist": list(PERSIST),
        "ir": "python3 炼蛊房/host_ir_check.py --case " + case,
        "c2": f"python3 炼蛊房/host_c2_verify.py check --case {case} --strict",
        "persist_skills": ["windows-persistence", "linux-post-exploit", "host-c2-verify"],
        "ir_local": bool(ir_local),
        "level": "L2" if ir_local else "L1",
        "ts": datetime.now(UTC).isoformat(),
        "skill": "傀舰队",
    }
    tag = _safe_host_tag(host)
    out = write_probe_json(rec, case=case, case_subdir="botnet_lab", filename=f"persist_{tag}.json")
    print(json.dumps({"host": host, "level": rec["level"], "out": str(out)}, ensure_ascii=False))
    return 0


def main() -> None:
    ap = argparse.ArgumentParser(description="授权 C2 舰队")
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fleet")
    f.add_argument("--host", action="append", required=True)
    f.add_argument("--case", required=True)
    f.add_argument("--os", default="linux")
    f.add_argument("--stack", default="sliver")
    f.add_argument("--edr", default="unknown")
    p = sub.add_parser("persist")
    p.add_argument("--host", required=True)
    p.add_argument("--case", required=True)
    p.add_argument("--local", action="store_true", help="本机已是授权机时顺带跑 host_ir_check")
    args = ap.parse_args()
    if args.cmd == "fleet":
        raise SystemExit(cmd_fleet(args))
    raise SystemExit(cmd_persist(args))


if __name__ == "__main__":
    main()
