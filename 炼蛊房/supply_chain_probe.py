#!/usr/bin/env python3
"""授权供链面：锁文件 / 安装脚本 / 未钉死 Action。不对外发包。

  python3 炼蛊房/supply_chain_probe.py list
  python3 炼蛊房/supply_chain_probe.py drive --path <仓根> --case <案>
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import write_probe_json  # noqa: E402


def _json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def scan(root: Path) -> dict:
    hits: list[str] = []
    pkg = root / "package.json"
    if pkg.is_file():
        data = _json(pkg)
        scripts = data.get("scripts") or {}
        for name in ("preinstall", "postinstall", "prepare", "install"):
            if name in scripts:
                hits.append(f"npm-{name}")
        deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        for n in deps:
            if n.startswith("@") and "//" not in n and len(n.split("/")) == 2:
                scope = n.split("/")[0]
                if scope in {"@internal", "@corp", "@private"}:
                    hits.append(f"scoped-{n}")
    req = root / "requirements.txt"
    if req.is_file():
        for ln in req.read_text(encoding="utf-8", errors="replace").splitlines():
            if ln.strip() and "==" not in ln and not ln.strip().startswith("#"):
                hits.append("pip-unpinned")
                break
    gomod = root / "go.mod"
    if gomod.is_file() and "replace " in gomod.read_text(encoding="utf-8", errors="replace"):
        hits.append("go-replace")
    wf = root / ".github" / "workflows"
    if wf.is_dir():
        blob = "\n".join(p.read_text(encoding="utf-8", errors="replace") for p in wf.glob("*.yml"))
        if re.search(r"uses:\s+\S+@v\d+\s*$", blob, re.M):
            hits.append("action-floating-tag")
        if re.search(r"uses:\s+\S+@[0-9a-f]{40}", blob):
            hits.append("action-pinned-sha")
    return {"hits": sorted(set(hits))}


def main() -> int:
    ap = argparse.ArgumentParser(description="授权供应链面")
    ap.add_argument("cmd", choices=("list", "drive"))
    ap.add_argument("--path", default=".")
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    if args.cmd == "list":
        print(json.dumps({"signals": ["npm-postinstall", "pip-unpinned", "go-replace", "action-floating-tag"]}, ensure_ascii=False, indent=2))
        return 0
    root = Path(args.path).resolve()
    if not root.is_dir():
        print("[!] --path 不是目录", file=sys.stderr)
        return 2
    info = scan(root)
    level = "L2" if info["hits"] else "none"
    rec = {"skill": "supply-chain-security", "root": str(root), **info, "level": level, "ts": datetime.now(UTC).isoformat()}
    out = write_probe_json(rec, case=args.case, out=args.out, case_subdir="supply", filename="chain.json")
    print(json.dumps({"level": level, "hits": info["hits"], "out": str(out)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
