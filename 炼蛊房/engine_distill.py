#!/usr/bin/env python3
"""测绘引擎整库蒸馏：盘点 Skill / Playbook / 工具 / 路由覆盖。

不扫 站点详情/、清晰入口/、00-工作台/、成功站点报告/、exports/。
不读 scope.company.json 正文。数字以本脚本 + skill_catalog 为准。

  python3 tools/ops/engine_distill.py snapshot
  python3 tools/ops/engine_distill.py orphans
  python3 tools/ops/engine_distill.py dirty
  python3 tools/ops/engine_distill.py --json /tmp/engine_distill.json
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Any

from scope_lib import is_oss_layout, repo_root
from skill_catalog import iter_skills
from skill_lane import classify as classify_lanes

ROOT = repo_root(Path(__file__))
SKIP_WALK = {
    "站点详情",
    "清晰入口",
    "00-工作台",
    "成功站点报告",
    "exports",
    ".git",
    "node_modules",
    "__pycache__",
}

# 入口路由真源：出现技能名即算「已挂」，家族细则不应再散挂 AGENTS
ROUTER_PATHS = (
    "AGENTS.md",
    "docs/playbooks/安全作业关键词分流手法.md",
    "docs/playbooks/案卷Triage与手法索引.md",
    "docs/playbooks/白标博彩家族与加密API分流.md",
    "docs/playbooks/打网站手法.md",
    "docs/playbooks/成套杀伤链手法.md",
    ".cursor/skills/keyword-router/SKILL.md",
    ".cursor/skills/gambling-family-router/SKILL.md",
    ".cursor/skills/extended-skill-router/SKILL.md",
    ".cursor/skills/web-vuln-router/SKILL.md",
    ".cursor/skills/ad-windows-router/SKILL.md",
    ".cursor/skills/wordpress-attack-router/SKILL.md",
    ".cursor/skills/attack-router/SKILL.md",
    ".cursor/skills/campaign-router/SKILL.md",
    ".cursor/skills/nine-stage-auto-router/SKILL.md",
    ".cursor/skills/shizhan-pack-router/SKILL.md",
    "docs/playbooks/实战技能包手法.md",
    "docs/learning/shizhan-pack/MAP.md",
    ".cursor/skills/hypothesis-ledger/SKILL.md",
    ".cursor/skills/engine-distill/SKILL.md",
    ".cursor/skills/skill-engineering/SKILL.md",
    ".cursor/skills/litellm-badhost/SKILL.md",
    ".cursor/skills/autonomous-social-engagement/SKILL.md",
    "docs/playbooks/假设驱动作业账本手法.md",
    "docs/learning/hypothesis-pack/MAP.md",
    "tools/ops/hypothesis_route.py",
    "tools/ops/se_skill_alias.py",
)

META_OPS = {
    "skill_catalog.py",
    "engine_distill.py",
    "css_query.py",
    "css_catalog.py",
    "skill_own.py",
    "skill_prune.py",
    "skill_store_sync.py",
    "skill_store_adopt.py",
    "skill_upgrade_kit.py",
    "skill_upgrade_thin.py",
    "skill_lane.py",
    "shizhan_pack_route.py",
    "shizhan_pack_fuse.py",
    "case_ledger.py",
    "hypothesis_route.py",
    "jwt_mask.py",
    "stdlib_fallback.py",
    "probe_http.py",
    "site_detail.py",
    "success_report_index.py",
    "extract_rar.py",
    "scope_stale_candidates.py",
    "bfwz_live_env.py",
}


def _read(rel: str) -> str:
    p = ROOT / rel
    if not p.is_file():
        return ""
    return p.read_text(encoding="utf-8", errors="replace")


def _count_lines(path: Path) -> int:
    if not path.is_file():
        return 0
    n = 0
    for ln in path.read_text(encoding="utf-8", errors="replace").splitlines():
        s = ln.strip()
        if s and not s.startswith("#"):
            n += 1
    return n


def _plays_dir() -> Path:
    return ROOT / "传承" if is_oss_layout() else ROOT / "docs" / "playbooks"


def _ops_dir() -> Path:
    return ROOT / "炼蛊房" if is_oss_layout() else ROOT / "tools" / "ops"


def _learn(*parts: str) -> Path:
    base = ROOT / "智道藏书" if is_oss_layout() else ROOT / "docs" / "learning"
    return base.joinpath(*parts)


def _listdir(path: Path) -> list[str]:
    if not path.is_dir():
        return []
    return sorted(
        p.name
        for p in path.iterdir()
        if p.is_dir() and not p.name.startswith(".") and p.name != "__pycache__"
    )


def _router_blob() -> str:
    parts = [_read(rel) for rel in ROUTER_PATHS]
    if is_oss_layout():
        naming = ROOT / "NAMING.json"
        if naming.is_file():
            parts.append(naming.read_text(encoding="utf-8", errors="replace"))
        plays = _plays_dir()
        if plays.is_dir():
            for p in sorted(plays.glob("*.md")):
                parts.append(p.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(parts)


def snapshot() -> dict[str, Any]:
    rows = iter_skills()
    grades = Counter(r["grade"] for r in rows)
    owned = [r for r in rows if r.get("owned")]
    biz = [r for r in rows if not r.get("owned")]
    stubs = [r for r in biz if r.get("stub")]
    fail = [r["name"] for r in rows if not r.get("valid")]
    thin = [r["name"] for r in rows if r["grade"] == "thin"]
    kit = [r["name"] for r in rows if r["grade"] == "kit"]

    pbs = sorted(p for p in _plays_dir().glob("*.md") if p.is_file())
    cve_daily = [
        p.name
        for p in pbs
        if p.name.startswith("CVE日报-") or p.name.startswith("房睇长·耳报-")
    ]
    methods = [p.name for p in pbs if not p.name.startswith("CVE日报-")]

    ops = sorted(
        p.name
        for p in _ops_dir().glob("*.py")
        if p.is_file() and not p.name.startswith("_")
    )
    tool_dirs = _listdir(ROOT / "tools")
    engine_mods = _listdir(ROOT / "engine")
    cli_py = (
        sorted(
            p.stem
            for p in (ROOT / "cli").glob("*.py")
            if p.stem not in {"__init__", "_helpers"}
        )
        if (ROOT / "cli").is_dir()
        else []
    )

    nine_stage = _learn("九转", "skills") if is_oss_layout() else _learn("nine-stage", "skills")
    if not nine_stage.is_dir():
        nine_stage = _learn("nine-stage", "skills")
    # assets/ 只有 html，不算技能
    nine_stage_n = (
        sum(
            1
            for p in nine_stage.iterdir()
            if p.is_dir()
            and not p.name.startswith(".")
            and p.name != "assets"
        )
        if nine_stage.is_dir()
        else 0
    )
    hyp_tech = (
        _learn("智道推演", "techniques")
        if is_oss_layout()
        else _learn("hypothesis-pack", "techniques")
    )
    if not hyp_tech.is_dir():
        hyp_tech = _learn("hypothesis-pack", "techniques")
    hyp_n = len(list(hyp_tech.glob("*.md"))) if hyp_tech.is_dir() else 0
    css = _learn("三十九门") if is_oss_layout() else _learn("cybersecurity-skills")
    if not css.is_dir():
        css = _learn("cybersecurity-skills")
    css_mods = 0
    css_skills = 0
    if css.is_dir():
        for m in css.iterdir():
            if m.is_dir() and re.match(r"^\d+", m.name):
                css_mods += 1
                sd = m / "skills"
                if sd.is_dir():
                    css_skills += sum(1 for x in sd.glob("*.md"))

    blob = _router_blob()
    routed_biz: list[str] = []
    orphan_biz: list[str] = []
    for r in biz:
        if r["grade"] == "stub":
            continue
        if r["name"] in blob:
            routed_biz.append(r["name"])
        else:
            orphan_biz.append(r["name"])

    skill_tools: set[str] = set()
    for r in rows:
        for t in r.get("tools") or []:
            skill_tools.add(Path(t).name)
    ops_loose = [
        n for n in ops if n not in skill_tools and n not in META_OPS
    ]

    sites_dir = ROOT / "config" / "scope_sites"
    scope_sites = (
        sum(
            1
            for p in sites_dir.iterdir()
            if p.suffix == ".json" and not p.name.startswith(".")
        )
        if sites_dir.is_dir()
        else 0
    )

    by_site = ROOT / "scripts" / "by_site"
    by_site_n = (
        sum(
            1
            for p in by_site.iterdir()
            if p.is_dir() and not p.name.startswith("_") and not p.name.startswith(".")
        )
        if by_site.is_dir()
        else 0
    )

    nuclei = ROOT / "tools" / "1day-kit" / "custom-templates"
    if not nuclei.is_dir() and is_oss_layout():
        nuclei = ROOT / "炼蛊房" / "1day-kit" / "custom-templates"
    nuclei_n = (
        len(list(nuclei.glob("*.yaml"))) + len(list(nuclei.glob("*.yml")))
        if nuclei.is_dir()
        else 0
    )
    lane_names = classify_lanes()
    lanes = {k: len(v) for k, v in lane_names.items()}

    return {
        "as_of": date.today().isoformat(),
        "skills": {
            "total": len(rows),
            "owned": len(owned),
            "biz": len(biz) - len(stubs),
            "stub": len(stubs),
            "grades": dict(grades),
            "fail": fail,
            "thin": thin,
            "kit": kit,
            "routed_biz": len(routed_biz),
            "orphan_biz": orphan_biz,
            "lanes": lanes,
            "attack_paper": lane_names["attack_paper"],
        },
        "playbooks": {
            "all": len(pbs),
            "methods": len(methods),
            "cve_daily": len(cve_daily),
        },
        "tools": {
            "ops_py": len(ops),
            "dirs": tool_dirs,
            "ops_not_in_skill": ops_loose,
            "custom_nuclei": nuclei_n,
        },
        "engine": {"mods": engine_mods, "cli": cli_py},
        "learning": {
            "nine_stage_skills": nine_stage_n,
            "css_modules": css_mods,
            "css_skill_md": css_skills,
            "hypothesis_tech": hyp_n,
        },
        "gate": {
            "proxy_nodes": _count_lines(ROOT / "config" / "proxy-nodes.txt"),
            "scope_sites": scope_sites,
            "by_site": by_site_n,
        },
    }


def _print_snapshot(data: dict[str, Any]) -> None:
    s = data["skills"]
    p = data["playbooks"]
    t = data["tools"]
    g = data["gate"]
    lrn = data["learning"]
    title = "大爱仙尊整库蒸馏" if is_oss_layout() else "测绘引擎整库蒸馏"
    print(f"{title}  as_of={data['as_of']}")
    print(
        f"skills total={s['total']} biz={s['biz']} stub={s['stub']} "
        f"owned={s['owned']} grades={s['grades']}"
    )
    print(f"fail={s['fail']}  thin={s['thin']}")
    ln = s.get("lanes") or {}
    print(
        f"lanes attack_ok={ln.get('attack_ok', 0)} "
        f"attack_paper={ln.get('attack_paper', 0)} "
        f"router={ln.get('router', 0)} "
        f"encyclopedia={ln.get('encyclopedia', 0)} "
        f"owned={ln.get('owned', 0)}"
    )
    if s.get("attack_paper"):
        print("attack_paper " + " ".join(s["attack_paper"]))
    print(
        f"routed_biz={s['routed_biz']}  orphan_biz={len(s['orphan_biz'])}"
    )
    print(
        f"playbooks all={p['all']} methods={p['methods']} "
        f"cve_daily={p['cve_daily']}"
    )
    print(
        f"ops_py={t['ops_py']} tool_dirs={len(t['dirs'])} "
        f"custom_nuclei={t['custom_nuclei']}"
    )
    print(
        f"engine_mods={len(data['engine']['mods'])} "
        f"cli={data['engine']['cli']}"
    )
    print(
        f"nine_stage={lrn['nine_stage_skills']} css_mod={lrn['css_modules']} "
        f"css_md={lrn['css_skill_md']} hypothesis_tech={lrn.get('hypothesis_tech', 0)}"
    )
    print(
        f"proxy_nodes={g['proxy_nodes']} scope_sites={g['scope_sites']} "
        f"by_site={g['by_site']}"
    )


_DIRTY_BUCKETS = (
    (".cursor/skills", "专卡，单独交"),
    (".cursor/rules", "规则，跟 AGENTS 一起"),
    ("清晰入口", "软链重建，后交或不交"),
    ("docs/playbooks", "手册，单独交"),
    ("docs/learning", "百科长文，可后交，不要和专卡捆"),
    ("docs/", "其它文档"),
    ("tools/ops", "探针，跟专卡一起"),
    ("tools/", "其它工具"),
    ("AGENTS.md", "真源"),
    ("README.md", "真源"),
    ("CLAUDE.md", "注入副本"),
    ("main.py", "测绘 CLI"),
    ("engine/", "测绘编排"),
    ("tests/", "单测"),
)


def _dirty_bucket(path: str) -> str:
    for prefix, _hint in _DIRTY_BUCKETS:
        if path == prefix or path.startswith(prefix.rstrip("/") + "/") or path.startswith(prefix):
            if prefix.endswith("/"):
                return prefix.rstrip("/")
            return prefix
    top = path.split("/", 1)[0]
    return top


def dirty_report() -> dict[str, Any]:
    """工作树按主题分桶。只统计，不 add / commit。"""
    proc = subprocess.run(
        ["git", "status", "--porcelain", "-uall"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "git status failed")
    counts: Counter[str] = Counter()
    for raw in proc.stdout.splitlines():
        if not raw:
            continue
        path = raw[3:].strip()
        if " -> " in path:
            path = path.split(" -> ", 1)[1]
        path = path.strip().strip('"')
        counts[_dirty_bucket(path)] += 1
    hints = {prefix.rstrip("/"): hint for prefix, hint in _DIRTY_BUCKETS}
    return {
        "total": sum(counts.values()),
        "buckets": dict(counts.most_common()),
        "hints": {k: hints[k] for k in counts if k in hints},
        "note": "按桶切开交，禁止一次交整树；exports/ 已 gitignore，不是案卷混盘。",
    }


def _print_dirty(data: dict[str, Any]) -> None:
    print(f"工作树未收拾  total={data['total']}")
    print(data["note"])
    hints = data.get("hints") or {}
    for name, n in (data.get("buckets") or {}).items():
        hint = hints.get(name, "")
        extra = f"  # {hint}" if hint else ""
        print(f"  {n:5d}  {name}{extra}")
    print("建议顺序：tools/ops + .cursor/skills → docs/playbooks → AGENTS/README → docs/learning")


def main() -> int:
    ap = argparse.ArgumentParser(
        description=("大爱仙尊" if is_oss_layout() else "SurveyEngine")
        + " whole-tree distill"
    )
    ap.add_argument(
        "cmd",
        nargs="?",
        default="snapshot",
        choices=("snapshot", "orphans", "dirty"),
    )
    ap.add_argument("--json", dest="json_out", default="")
    args = ap.parse_args()
    if args.cmd == "dirty":
        data = dirty_report()
        if args.json_out:
            Path(args.json_out).write_text(
                json.dumps(data, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            print(f"[+] json -> {args.json_out}")
        _print_dirty(data)
        return 0
    data = snapshot()
    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(data, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"[+] json -> {args.json_out}")
    if args.cmd == "orphans":
        print(f"orphan_biz={len(data['skills']['orphan_biz'])}")
        for n in data["skills"]["orphan_biz"]:
            print(n)
        print(f"ops_not_in_skill={len(data['tools']['ops_not_in_skill'])}")
        for n in data["tools"]["ops_not_in_skill"]:
            print(f"  {n}")
        return 0
    _print_snapshot(data)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n中断")
    except SystemExit:
        raise
    except Exception as exc:
        print(f"[!] {exc}")
        raise SystemExit(1)
