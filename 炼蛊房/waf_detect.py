#!/usr/bin/env python3
"""授权闸门下的 WAF 检测封装（包装 vendor waf_hunter）。

对齐 Playbook：传承/隐鳞·罩.md
知识真源：tools/vendor/09-aux/waf-detector/SKILL.full.md

示例:
  python3 炼蛊房/waf_detect.py stats
  python3 炼蛊房/waf_detect.py detect --url https://授权站 --case <案卷>
  python3 炼蛊房/waf_detect.py full   --url https://授权站 --case <案卷> --attack sqli
  python3 炼蛊房/waf_detect.py bypass --waf cloudflare --attack sqli --case <案卷>
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, UTC
from pathlib import Path

OPS = Path(__file__).resolve().parent
ENGINE = (OPS.parent if (OPS.parent / "杀招").is_dir() else (OPS.parent if (OPS.parent / "杀招").is_dir() else OPS.parents[1]))
VENDOR = ENGINE / "tools" / "vendor" / "09-aux" / "waf-detector"
HUNTER = VENDOR / "waf_hunter.py"

if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))

from scope_lib import host_of, in_scope  # noqa: E402


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def case_dir(case: str) -> Path:
    d = ENGINE / "案卷" / case / "测绘" / "waf"
    d.mkdir(parents=True, exist_ok=True)
    return d


def ensure_scope(url: str) -> None:
    h = host_of(url)
    if not h:
        raise SystemExit("[scope] 无法解析 host")
    if h in ("127.0.0.1", "localhost", "::1"):
        return
    if not in_scope(h):
        raise SystemExit(f"[scope] {h} 不在授权范围，拒绝请求")


def run_hunter(argv: list[str]) -> int:
    if not HUNTER.is_file():
        raise SystemExit(f"[err] 缺少 {HUNTER}")
    cmd = [sys.executable, str(HUNTER), *argv]
    print(f"[waf_detect] {' '.join(cmd)}", flush=True)
    return subprocess.call(cmd, cwd=str(VENDOR))


def cmd_stats(_: argparse.Namespace) -> int:
    return run_hunter(["stats"])


def cmd_list(args: argparse.Namespace) -> int:
    argv = ["list"]
    if args.category:
        argv += ["--category", args.category]
    return run_hunter(argv)


def cmd_detect(args: argparse.Namespace) -> int:
    ensure_scope(args.url)
    out_dir = case_dir(args.case)
    out = out_dir / "detect.json"
    argv = [
        "detect",
        "-t",
        args.url,
        "--format",
        "json",
        "-o",
        str(out),
    ]
    if args.insecure:
        argv.append("--insecure")
    if args.verbose:
        argv.append("-v")
    rc = run_hunter(argv)
    meta = {
        "ts": _now(),
        "url": args.url,
        "host": host_of(args.url),
        "output": str(out.relative_to(ENGINE)),
        "rc": rc,
        "next": [
            "识别到 WAF 后：waf_detect.py bypass --waf <名> --attack sqli",
            "SQLi 被拦：优先 炼蛊房/waf_sqli_bypass.py（Unicode/换行）",
            "CDN 挡路：炼蛊房/origin_recon.py / space_search.py cert-origin",
        ],
    }
    (out_dir / "meta.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"[ok] evidence → {out_dir}")
    return rc


def cmd_full(args: argparse.Namespace) -> int:
    ensure_scope(args.url)
    out_dir = case_dir(args.case)
    out = out_dir / "full.json"
    argv = [
        "full",
        "-t",
        args.url,
        "--format",
        "json",
        "-o",
        str(out),
        "--attack",
        args.attack,
    ]
    if args.insecure:
        argv.append("--insecure")
    if args.verbose:
        argv.append("-v")
    rc = run_hunter(argv)
    meta = {
        "ts": _now(),
        "url": args.url,
        "host": host_of(args.url),
        "attack": args.attack,
        "output": str(out.relative_to(ENGINE)),
        "rc": rc,
    }
    (out_dir / "full_meta.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"[ok] evidence → {out_dir}")
    return rc


def cmd_bypass(args: argparse.Namespace) -> int:
    out_dir = case_dir(args.case) if args.case else None
    argv = ["bypass", "--attack", args.attack]
    if args.waf:
        argv += ["--waf", args.waf]
    if args.url:
        ensure_scope(args.url)
        argv += ["-t", args.url]
    if out_dir:
        out = out_dir / f"bypass_{args.attack}.json"
        argv += ["--format", "json", "-o", str(out)]
    if args.insecure:
        argv.append("--insecure")
    return run_hunter(argv)


def cmd_verify(args: argparse.Namespace) -> int:
    ensure_scope(args.url)
    out_dir = case_dir(args.case)
    out = out_dir / "verify.json"
    argv = ["verify", "-t", args.url, "--format", "json", "-o", str(out)]
    if args.insecure:
        argv.append("--insecure")
    return run_hunter(argv)


def main() -> int:
    p = argparse.ArgumentParser(description="大爱仙尊 WAF 检测（授权闸门 + waf_hunter）")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("stats", help="指纹库统计").set_defaults(func=cmd_stats)

    sp_list = sub.add_parser("list", help="列出 WAF")
    sp_list.add_argument("--category", help="cloud/hardware/software/cdn")
    sp_list.set_defaults(func=cmd_list)

    sp_d = sub.add_parser("detect", help="单目标检测（需授权）")
    sp_d.add_argument("--url", required=True)
    sp_d.add_argument("--case", required=True, help="案卷名，证据落 案卷/<case>/案卷/waf/")
    sp_d.add_argument("--insecure", action="store_true")
    sp_d.add_argument("-v", "--verbose", action="store_true")
    sp_d.set_defaults(func=cmd_detect)

    sp_f = sub.add_parser("full", help="检测+绕过建议（需授权）")
    sp_f.add_argument("--url", required=True)
    sp_f.add_argument("--case", required=True)
    sp_f.add_argument("--attack", default="sqli", choices=["sqli", "xss", "lfi", "rce", "ssrf", "ssti", "cmdi"])
    sp_f.add_argument("--insecure", action="store_true")
    sp_f.add_argument("-v", "--verbose", action="store_true")
    sp_f.set_defaults(func=cmd_full)

    sp_b = sub.add_parser("bypass", help="生成绕过 Payload（无 URL 时不触网）")
    sp_b.add_argument("--waf", help="如 cloudflare / 阿里云 WAF")
    sp_b.add_argument("--attack", default="sqli")
    sp_b.add_argument("--url", help="可选；有则过授权闸门")
    sp_b.add_argument("--case", help="可选；有则落证据")
    sp_b.add_argument("--insecure", action="store_true")
    sp_b.set_defaults(func=cmd_bypass)

    sp_v = sub.add_parser("verify", help="误报验证（需授权）")
    sp_v.add_argument("--url", required=True)
    sp_v.add_argument("--case", required=True)
    sp_v.add_argument("--insecure", action="store_true")
    sp_v.set_defaults(func=cmd_verify)

    args = p.parse_args()
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
