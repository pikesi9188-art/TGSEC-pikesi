#!/usr/bin/env python3
"""HITCON 手法族串联：授权站一次跑完未修高频面。

不打通报厂商。各子探针自己过 scope。
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, UTC
from pathlib import Path
import importlib
from types import SimpleNamespace
from typing import Any

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import host_of, in_scope, write_probe_json  # noqa: E402

PROBES: list[tuple[str, str]] = (
    ("ollama", "ollama_unauth_probe"),
    ("php_cgi", "php_cgi_4577_probe"),
    ("wp_xmlrpc", "wp_xmlrpc_probe"),
    ("client_state", "client_state_skip_probe"),
    ("dir_dump", "sensitive_dir_dump_probe"),
    ("reset_token", "reset_token_surface_probe"),
    ("trust_ip", "trusted_ip_header_probe"),
    ("open_redirect", "open_redirect_surface_probe"),
)


def _run_one(mod_name: str, base: str, case: str) -> dict[str, Any]:
    mod = importlib.import_module(mod_name)
    args = SimpleNamespace(base=base, case=case, out=None)
    try:
        return mod.run(args) or {}
    except SystemExit as e:
        return {"level": "skip", "error": f"exit {e.code}"}
    except Exception as e:
        return {"level": "error", "error": str(e)[:160]}


def run(args: argparse.Namespace) -> dict[str, Any]:
    host = host_of(args.base)
    if not host or not in_scope(host):
        print(f"[!] 不在 scope：{host or args.base}", file=sys.stderr)
        sys.exit(2)
    summary: dict[str, Any] = {}
    best = "none"
    order = {"L2": 2, "L1": 1, "note": 0, "none": 0, "skip": 0, "error": 0}
    for key, mod in PROBES:
        print(f"[*] {key}")
        rep = _run_one(mod, args.base, args.case)
        lvl = str(rep.get("level") or "none")
        summary[key] = {
            "level": lvl,
            "error": rep.get("error", ""),
            "hint": (rep.get("next") or "")[:80],
        }
        if order.get(lvl, 0) > order.get(best, 0):
            best = lvl
    report = {
        "target": args.base.rstrip("/"),
        "ts": datetime.now(UTC).isoformat(),
        "level": best,
        "probes": summary,
        "playbook": "传承/洞会·无日.md",
        "next": "看 probes.*.level==L2 的专卡深挖；禁止扩 HITCON 厂商。",
    }
    out_path = write_probe_json(
        report, case=args.case, out=args.out, case_subdir="hitcon", filename="chain.json",
    )
    print(json.dumps({"level": best, "probes": {k: v["level"] for k, v in summary.items()}, "out": str(out_path)}, ensure_ascii=False))
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="HITCON 未修族串联（授权站）")
    ap.add_argument("--base", required=True)
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    run(args)


if __name__ == "__main__":
    main()
