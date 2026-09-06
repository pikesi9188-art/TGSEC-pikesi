#!/usr/bin/env python3
"""进内网后的快速存活/端口/服务探测（通过 SOCKS5 隧道）。

前置：tunnel-kit 已建立 SOCKS5（chisel/frp/ligolo），proxychains4 已安装。

示例:
  python3 tools/tunnel-kit/internal_scan.py doctor
  python3 tools/tunnel-kit/internal_scan.py portscan --cidr 10.0.0.0/24 --socks 127.0.0.1:1080 --case <案卷>
  python3 tools/tunnel-kit/internal_scan.py ping    --cidr 10.0.0.0/24 --socks 127.0.0.1:1080 --case <案卷>
  python3 tools/tunnel-kit/internal_scan.py webfp   --targets targets.txt --socks 127.0.0.1:1080 --case <案卷>
  python3 tools/tunnel-kit/internal_scan.py lateral --target 10.0.0.5 --socks 127.0.0.1:1080 --case <案卷>
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
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

OPS = _kit_ops_dir(Path(__file__))
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def case_dir(case: str) -> Path:
    d = (ENGINE / "案卷" if (ENGINE / "案卷").is_dir() else ENGINE / "exports" / "bot-recovery") / case / "测绘" / "internal"
    d.mkdir(parents=True, exist_ok=True)
    return d


def find_tool(name: str) -> str | None:
    for p in (ARSENAL_BIN / name, Path(shutil.which(name) or "")):
        if p and Path(p).is_file() and os.access(p, os.X_OK):
            return str(p)
    return None


def run(cmd: list[str], timeout: int = 300, env: dict | None = None) -> tuple[int, str]:
    try:
        merged_env = dict(os.environ)
        if env:
            merged_env.update(env)
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=merged_env)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    except FileNotFoundError:
        return 127, f"not found: {cmd[0]}"


def proxychains_prefix(socks: str, tmp_dir: Path) -> list[str]:
    """返回 proxychains4 前缀；若无则返回空列表（调用方走工具原生 proxy 参数）。"""
    pc = find_tool("proxychains4") or find_tool("proxychains")
    if not pc:
        return []
    cfg = build_proxychains_conf(socks, tmp_dir)
    return [pc, "-f", str(cfg), "-q"]


def build_proxychains_conf(socks: str, tmp_dir: Path) -> Path:
    host, port = (socks.split(":") + ["1080"])[:2]
    cfg = tmp_dir / "proxychains.conf"
    cfg.write_text(
        f"strict_chain\nquiet_mode\nproxy_dns\n[ProxyList]\nsocks5 {host} {port}\n",
        encoding="utf-8",
    )
    return cfg


def cmd_doctor(_: argparse.Namespace) -> int:
    tools = {
        "nmap": find_tool("nmap"),
        "naabu": find_tool("naabu"),
        "httpx": find_tool("httpx"),
        "netexec": find_tool("netexec") or find_tool("crackmapexec"),
        "proxychains4": find_tool("proxychains4") or find_tool("proxychains"),
    }
    missing = []
    for name, path in tools.items():
        print(f"[{'ok' if path else 'missing'}] {name}: {path or '-'}")
        if not path:
            missing.append(name)
    hints = {
        "naabu": "bash tools/tunnel-kit/install_tunnels.sh  # 或 brew install naabu",
        "nmap": "brew install nmap  或已在 arsenal",
        "httpx": "arsenal 中已有 httpx；或 go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "netexec": "pip install netexec  或 pip install crackmapexec",
        "proxychains4": "brew install proxychains-ng",
    }
    for m in missing:
        print(f"  hint: {hints.get(m, 'install manually')}")
    print("[ok] internal_scan ready (some tools optional)" if "nmap" not in missing or "naabu" not in missing
          else "[warn] both nmap and naabu missing — install at least one port scanner")
    return 0


def cmd_ping(args: argparse.Namespace) -> int:
    """用 nmap ping 扫描 CIDR 存活，通过 proxychains 或 nmap --proxies。"""
    nmap = find_tool("nmap")
    if not nmap:
        raise SystemExit("[err] nmap not found")
    out_dir = case_dir(args.case)
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        prefix = proxychains_prefix(args.socks, Path(tmp))
        out_xml = out_dir / "ping_scan.xml"
        cmd = prefix + [nmap, "-sn", "-T4", "--open", "-oX", str(out_xml), args.cidr]
        # nmap 支持 --proxies 参数（TCP 扫描时）；ping 扫描需要 proxychains
        if not prefix and args.socks:
            print(f"[warn] proxychains not found; nmap ping scan may bypass SOCKS — install proxychains-ng for accurate results", flush=True)
        if args.exclude:
            cmd += ["--exclude", args.exclude]
        print("[*]", " ".join(cmd), flush=True)
        rc, out = run(cmd, timeout=600)
        (out_dir / "ping_scan.log").write_text(out, encoding="utf-8")
        hosts = []
        if out_xml.is_file():
            import re
            hosts = re.findall(r'addr="([\d.]+)"', out_xml.read_text())
        result = {"ts": _now(), "cidr": args.cidr, "socks": args.socks,
                  "alive_hosts": list(set(hosts)), "count": len(set(hosts))}
        (out_dir / "alive_hosts.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return rc


def cmd_portscan(args: argparse.Namespace) -> int:
    """端口扫描：优先 naabu（快），回退 nmap。"""
    naabu = find_tool("naabu")
    nmap = find_tool("nmap")
    out_dir = case_dir(args.case)
    import tempfile

    ports = args.ports or "21,22,23,25,80,443,445,1433,1521,3306,3389,5432,5900,6379,8080,8443,8888,9200,27017"

    with tempfile.TemporaryDirectory() as tmp:
        prefix = proxychains_prefix(args.socks, Path(tmp))

        if naabu:
            out_json = out_dir / "ports.json"
            # naabu 原生支持 -proxy socks5://host:port
            proxy_args = ["-proxy", f"socks5://{args.socks}"] if args.socks and not prefix else []
            cmd = prefix + [naabu, "-host", args.cidr, "-p", ports] + proxy_args + [
                "-json", "-o", str(out_json), "-silent",
            ]
            print("[*]", " ".join(cmd), flush=True)
            rc, out = run(cmd, timeout=900)
            (out_dir / "ports.log").write_text(out, encoding="utf-8")
        elif nmap:
            out_xml = out_dir / "ports.xml"
            cmd = prefix + [nmap, "-sT", "-Pn", "-T3", "-p", ports,
                             "--open", "-oX", str(out_xml), args.cidr]
            print("[*]", " ".join(cmd), flush=True)
            rc, out = run(cmd, timeout=1200)
            (out_dir / "ports.log").write_text(out, encoding="utf-8")
        else:
            raise SystemExit("[err] naabu 和 nmap 都未找到")

    print(f"[done] rc={rc} out={out_dir}")
    print(f"[next] python3 tools/tunnel-kit/internal_scan.py webfp --targets {out_dir}/ports.json ...")
    return rc


def cmd_webfp(args: argparse.Namespace) -> int:
    """对端口列表跑 httpx 服务指纹识别（通过 proxychains）。"""
    httpx = find_tool("httpx")
    if not httpx:
        raise SystemExit("[err] httpx not found — source scripts/arsenal-env.sh")
    out_dir = case_dir(args.case)
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        prefix = proxychains_prefix(args.socks, Path(tmp))
        # httpx 原生支持 -http-proxy / -socks5-proxy
        proxy_args = ["-socks5-proxy", f"socks5://{args.socks}"] if args.socks and not prefix else []
        out_json = out_dir / "webfp.json"
        cmd = prefix + proxy_args + [
            httpx,
            "-l", args.targets,
            "-json",
            "-o", str(out_json),
            "-title", "-tech-detect", "-status-code",
            "-timeout", str(int(args.timeout)),
            "-silent",
        ]
        print("[*]", " ".join(cmd), flush=True)
        rc, out = run(cmd, timeout=600)
        (out_dir / "webfp.log").write_text(out, encoding="utf-8")
    count = 0
    if out_json.is_file():
        count = sum(1 for _ in out_json.open(encoding="utf-8") if _.strip())
    print(f"[done] rc={rc} services={count} out={out_json}")
    return rc


def cmd_lateral(args: argparse.Namespace) -> int:
    """netexec / crackmapexec 横向（SMB 弱口令 / 共享枚举）。"""
    nxc = find_tool("netexec") or find_tool("crackmapexec")
    if not nxc:
        raise SystemExit("[err] netexec/cme not found — pip install netexec")
    out_dir = case_dir(args.case)
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        prefix = proxychains_prefix(args.socks, Path(tmp))
        # 枚举共享
        cmd_enum = prefix + [nxc, "smb", args.target, "--shares"]
        if args.user:
            cmd_enum += ["-u", args.user, "-p", args.password or ""]
        print("[*]", " ".join(cmd_enum), flush=True)
        rc, out = run(cmd_enum, timeout=60)
        (out_dir / f"lateral_{args.target}_shares.txt").write_text(out, encoding="utf-8")
        print(out[:2000])
    return rc


def main() -> int:
    p = argparse.ArgumentParser(description="内网扫描（SOCKS5 通道）")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("doctor")
    d.set_defaults(func=cmd_doctor)

    pg = sub.add_parser("ping", help="存活扫描 CIDR")
    pg.add_argument("--cidr", required=True)
    pg.add_argument("--socks", default="127.0.0.1:1080")
    pg.add_argument("--case", required=True)
    pg.add_argument("--exclude", default="")
    pg.set_defaults(func=cmd_ping)

    ps = sub.add_parser("portscan", help="端口扫描")
    ps.add_argument("--cidr", required=True)
    ps.add_argument("--ports", default="")
    ps.add_argument("--socks", default="127.0.0.1:1080")
    ps.add_argument("--case", required=True)
    ps.set_defaults(func=cmd_portscan)

    wf = sub.add_parser("webfp", help="Web 服务指纹")
    wf.add_argument("--targets", required=True, help="地址列表文件或 naabu json")
    wf.add_argument("--socks", default="127.0.0.1:1080")
    wf.add_argument("--case", required=True)
    wf.add_argument("--timeout", type=float, default=5.0)
    wf.set_defaults(func=cmd_webfp)

    lt = sub.add_parser("lateral", help="SMB 横向 / 共享枚举（netexec）")
    lt.add_argument("--target", required=True)
    lt.add_argument("--socks", default="127.0.0.1:1080")
    lt.add_argument("--case", required=True)
    lt.add_argument("--user", default="")
    lt.add_argument("--password", default="")
    lt.set_defaults(func=cmd_lateral)

    args = p.parse_args()
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
