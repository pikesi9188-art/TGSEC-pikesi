#!/usr/bin/env python3
"""技能目录 + 校验（对照 skill-main 的商店工程，适配本库作业卡）。

list / validate / export。不扫 站点详情/、exports/、清晰入口/。
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from pathlib import Path
from typing import Any

from scope_lib import is_oss_layout, repo_root

ROOT = repo_root(Path(__file__))
SKILLS = ROOT / "杀招" if is_oss_layout() else ROOT / ".cursor" / "skills"
STORE = (
    ROOT / "智道藏书" / "skill-store"
    if is_oss_layout()
    else ROOT / "docs" / "learning" / "skill-store"
)
# 本库允许数字开头（1day / 666bet），比 skill-main 的 ^[a-z] 宽
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]*[a-z0-9]$|^[a-z0-9]$")
# 只认 stub 卡头「本卡仅重定向」。主卡写「旧名 x 已并入」不能当 stub。
STUB_HINTS = ("本卡仅重定向",)


def _split_frontmatter(text: str) -> tuple[str, str]:
    m = re.match(r"^\s*---\s*\n(.*?)\n---\s*\n?(.*)", text, re.DOTALL)
    if not m:
        return "", text
    return m.group(1), m.group(2)


def _fm_field(fm: str, key: str) -> str:
    m = re.search(
        rf"(?ms)^{re.escape(key)}:\s*([|>][-+]?)\s*\n((?:[ \t]+.*\n?)*)",
        fm,
    )
    if m:
        return " ".join(ln.strip() for ln in m.group(2).splitlines() if ln.strip())
    m = re.search(rf"(?m)^{re.escape(key)}:\s*(.+?)\s*$", fm)
    if m:
        val = m.group(1).strip().strip("'\"")
        if val not in (">", ">-", "|", "|-", ">+", "|+"):
            return val
    return ""


def _find_skill_md(skill_dir: Path) -> Path | None:
    direct = skill_dir / "SKILL.md"
    if direct.is_file():
        return direct
    nested = skill_dir / skill_dir.name / "SKILL.md"
    if nested.is_file():
        return nested
    for child in skill_dir.iterdir():
        cand = child / "SKILL.md"
        if child.is_dir() and cand.is_file():
            return cand
    return None


_REF_TRAIL = "。；，、.:;"
_REF_PLACEHOLDER = re.compile(r"[<>]|YYYY-MM-DD")


def _clean_ref(p: str) -> str | None:
    p = (p or "").split()[0].split("#")[0]
    p = re.split(r"[。；，、]", p)[0].rstrip(_REF_TRAIL)
    if not p or _REF_PLACEHOLDER.search(p):
        return None
    return p


def _refs(body: str) -> dict[str, list[str]]:
    raw_pb = (
        re.findall(r"docs/playbooks/[^\s)`'\"]+", body)
        + re.findall(r"docs/learning/[^\s)`'\"]+", body)
        + re.findall(r"传承/[^\s)`'\"]+", body)
        + re.findall(r"智道藏书/[^\s)`'\"]+", body)
    )
    playbooks = sorted({p for p in (_clean_ref(x) for x in raw_pb) if p})
    raw_tools = (
        re.findall(r"(?<![A-Za-z0-9_/])tools/(?:ops/)?[A-Za-z0-9_./-]+\.py", body)
        + re.findall(r"(?<![A-Za-z0-9_/])炼蛊房/[A-Za-z0-9_./-]+\.py", body)
        + re.findall(r"`python3\s+(tools/[^\s`]+)`", body)
        + re.findall(r"`python3\s+(炼蛊房/[^\s`]+)`", body)
        + re.findall(r"docs/learning/skill-store/[^\s)`'\"]+\.py", body)
    )
    tools = []
    for x in raw_tools:
        p = _clean_ref(x)
        if not p:
            continue
        # 商店卡相对路径：`{baseDir}/tools/...`，不是仓库根下的探针
        if "{baseDir}/" + p in body:
            continue
        tools.append(p)
    return {"playbooks": playbooks, "tools": sorted(set(tools))}


def inspect_one(skill_dir: Path) -> dict[str, Any]:
    name = skill_dir.name
    md = _find_skill_md(skill_dir)
    rec: dict[str, Any] = {
        "name": name,
        "path": str(skill_dir.relative_to(ROOT)),
        "skill_md": str(md.relative_to(ROOT)) if md else "",
        "has_frontmatter": False,
        "description": "",
        "lines": 0,
        "headings": 0,
        "has_scripts": (skill_dir / "scripts").is_dir()
        and any((skill_dir / "scripts").rglob("*")),
        "has_references": any(
            (skill_dir / n).exists()
            for n in ("references", "reference.md", "examples.md")
        ),
        "stub": False,
        "grade": "thin",
        "playbooks": [],
        "tools": [],
        "errors": [],
        "warnings": [],
        "owned": False,
    }
    if not md:
        rec["errors"].append("Missing required file: SKILL.md")
        rec["grade"] = "broken"
        return rec

    text = md.read_text(encoding="utf-8", errors="replace")
    fm, body = _split_frontmatter(text)
    rec["has_frontmatter"] = bool(fm)
    rec["owned"] = "pack: survey-skill" in (fm or "") or "owned: true" in (fm or "")
    rec["description"] = _fm_field(fm, "description") if fm else ""
    rec["fm_name"] = _fm_field(fm, "name") if fm else ""
    rec["lines"] = len(body.splitlines())
    rec["headings"] = len(re.findall(r"(?m)^#+ ", body))
    refs = _refs(text)
    rec["playbooks"] = refs["playbooks"]
    rec["tools"] = refs["tools"]
    blob = text
    rec["stub"] = any(h in blob for h in STUB_HINTS) and rec["lines"] < 40

    if rec["stub"]:
        rec["grade"] = "stub"
    elif rec["playbooks"] and (rec["tools"] or rec["has_scripts"]):
        rec["grade"] = "full"
    elif rec["playbooks"] or rec["tools"] or rec["has_scripts"]:
        rec["grade"] = "kit"
    else:
        rec["grade"] = "thin"
    return rec


def validate_one(rec: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = list(rec.get("errors") or [])
    warnings: list[str] = list(rec.get("warnings") or [])
    if rec.get("grade") == "broken":
        rec["valid"] = False
        rec["errors"] = errors
        rec["warnings"] = warnings
        return rec

    if not rec["has_frontmatter"]:
        errors.append("SKILL.md must start with YAML frontmatter (---)")
    fm_name = rec.get("fm_name") or ""
    if not fm_name:
        errors.append("Missing required field: name")
    elif not NAME_RE.match(fm_name):
        if is_oss_layout():
            warnings.append(f"开源挂号名 '{fm_name}'，机器名见 NAMING.json")
        elif NAME_RE.match(rec["name"]):
            warnings.append(
                f"frontmatter name '{fm_name}' 按目录 '{rec['name']}' 计"
            )
        else:
            errors.append(
                f"Skill name '{fm_name}' must be lowercase letters, digits, hyphens"
            )
    elif fm_name != rec["name"] and rec["name"] not in (fm_name,):
        warnings.append(f"Directory '{rec['name']}' != frontmatter name '{fm_name}'")
    desc = rec.get("description") or ""
    if not desc:
        errors.append("Missing required field: description")
    elif len(desc) < 10:
        errors.append("Description too short (<10 chars)")
    elif len(desc) > 500:
        warnings.append("Description too long (>500 chars)")
    if rec["lines"] < 10 and not rec["stub"]:
        errors.append(f"Content too short ({rec['lines']} lines < 10)")
    if rec["headings"] < 1:
        errors.append("Content must have at least one heading")
    if rec["grade"] == "thin":
        warnings.append("thin: 无 Playbook 也无工具入口（交货不算完整）")
    for kind, paths in (
        ("playbook", rec.get("playbooks") or []),
        ("tool", rec.get("tools") or []),
    ):
        for rel in paths:
            rel = _clean_ref(rel) or ""
            if not rel:
                continue
            target = ROOT / rel
            if not target.is_file() and not target.is_dir():
                warnings.append(f"dangling {kind}: {rel}")
    rec["errors"] = errors
    rec["warnings"] = warnings
    rec["valid"] = not errors
    return rec


def iter_skills() -> list[dict[str, Any]]:
    if not SKILLS.is_dir():
        return []
    out = []
    for p in sorted(SKILLS.iterdir()):
        if not p.is_dir() or p.name.startswith("_") or p.name.startswith("."):
            continue
        out.append(validate_one(inspect_one(p)))
    return out


def _print_table(rows: list[dict[str, Any]]) -> None:
    print(f"{'grade':6} {'name':36} pb tool scr stub err warn")
    for r in rows:
        print(
            f"{r['grade']:6} {r['name'][:36]:36} "
            f"{len(r['playbooks']):2} {len(r['tools']):4} "
            f"{int(r['has_scripts']):3} {int(r['stub']):4} "
            f"{len(r['errors']):3} {len(r['warnings']):4}"
        )
    c: dict[str, int] = {}
    for r in rows:
        c[r["grade"]] = c.get(r["grade"], 0) + 1
    print("---")
    print(
        f"total={len(rows)} full={c.get('full', 0)} kit={c.get('kit', 0)} "
        f"thin={c.get('thin', 0)} stub={c.get('stub', 0)} broken={c.get('broken', 0)}"
    )


def _to_md(rows: list[dict[str, Any]]) -> str:
    lines = [
        f"# {'大爱仙尊' if is_oss_layout() else '测绘引擎'}技能目录（skill_catalog 生成）",
        "",
        f"共 {len(rows)} 张。grade：full=Playbook+工具，kit=有其一，thin=只有正文，stub=重定向。",
        "",
        "| grade | name | description | playbook | tool |",
        "|-------|------|-------------|----------|------|",
    ]
    for r in rows:
        desc = (r.get("description") or "").replace("|", "\\|")[:80]
        pb = r["playbooks"][0] if r["playbooks"] else ""
        tool = r["tools"][0] if r["tools"] else ("scripts/" if r["has_scripts"] else "")
        lines.append(f"| {r['grade']} | `{r['name']}` | {desc} | {pb} | {tool} |")
    return "\n".join(lines) + "\n"


def write_clear_entry_indexes(rows: list[dict[str, Any]], dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    owned = [r for r in rows if r.get("owned")]
    biz = [r for r in rows if not r.get("owned")]
    stubs = [r for r in biz if r.get("stub")]

    def _table(items: list[dict[str, Any]]) -> list[str]:
        lines = [
            "| 层 | name | description |",
            "|----|------|-------------|",
        ]
        for r in items:
            layer = "通用" if r.get("owned") else ("重定向" if r.get("stub") else "打站")
            desc = (r.get("description") or "").replace("|", "\\|")[:90]
            lines.append(f"| {layer} | `{r['name']}` | {desc} |")
        return lines

    all_md = [
        f"# {'大爱仙尊' if is_oss_layout() else '测绘引擎'}技能总目录",
        "",
        f"共 **{len(rows)}** 张（清晰入口能点开的完整清单）。",
        f"打站专卡 {len(biz) - len(stubs)} + stub {len(stubs)} + 已收编通用 {len(owned)}。",
        "",
        "Finder 里「清晰入口」按主题分子目录放作业软链；**全部技能名单在本文件**。",
        "真路径：`.cursor/skills/<name>/SKILL.md`",
        "",
        * _table(rows),
        "",
    ]
    (dest / "技能总目录.md").write_text("\n".join(all_md), encoding="utf-8")
    biz_md = [
        "# 打站专卡目录",
        "",
        f"共 **{len(biz)}** 张（不含已收编通用卡）。",
        "",
        * _table(biz),
        "",
    ]
    (dest / "打站专卡目录.md").write_text("\n".join(biz_md), encoding="utf-8")
    gen_md = [
        "# 通用技能目录（已收编）",
        "",
        f"共 **{len(owned)}** 张，frontmatter 带 `pack: survey-skill`。",
        "",
        * _table(owned),
        "",
    ]
    (dest / "通用技能目录.md").write_text("\n".join(gen_md), encoding="utf-8")
    print(f"[+] 清晰入口目录 all={len(rows)} biz={len(biz)} owned={len(owned)}")


def rebuild_store_catalog() -> dict[str, Any]:
    skills_dir = STORE / "skills"
    owned_src: dict[str, str] = {}
    owned_path = STORE / "owned.json"
    if owned_path.is_file():
        for s in json.loads(owned_path.read_text(encoding="utf-8")).get("skills") or []:
            key = s.get("name") or s.get("id") or ""
            if key:
                owned_src[key] = s.get("source") or ""
    recs = []
    if skills_dir.is_dir():
        for p in sorted(skills_dir.iterdir()):
            md = p / "SKILL.md"
            if not p.is_dir() or not md.is_file():
                continue
            text = md.read_text(encoding="utf-8", errors="replace")
            recs.append(
                {
                    "id": p.name,
                    "name": p.name,
                    "source": owned_src.get(p.name, ""),
                    "description": _fm_field(_split_frontmatter(text)[0], "description"),
                    "files": sum(1 for _ in p.rglob("*") if _.is_file()),
                }
            )
    payload = {
        "generated_by": "skill_catalog.py doctor",
        "count": len(recs),
        "skills": recs,
    }
    if not STORE.is_dir():
        return payload
    (STORE / "catalog.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return payload


def doctor(*, fix: bool) -> int:
    owned_path = STORE / "owned.json"
    owned = []
    if owned_path.is_file():
        owned = json.loads(owned_path.read_text(encoding="utf-8")).get("skills") or []
    keep_ids = {s.get("id") for s in owned if s.get("id")}
    skills_dir = STORE / "skills"
    pruned = 0
    if skills_dir.is_dir() and keep_ids:
        for p in list(skills_dir.iterdir()):
            if p.is_dir() and p.name not in keep_ids:
                if fix:
                    shutil.rmtree(p)
                    pruned += 1
                else:
                    pruned += 1
    cat = rebuild_store_catalog()
    rows = iter_skills()
    fail = [r["name"] for r in rows if not r["valid"]]
    if fix:
        for name in fail:
            md = SKILLS / name / "SKILL.md"
            if not md.is_file():
                continue
            text = md.read_text(encoding="utf-8", errors="replace")
            if text.lstrip().startswith("---"):
                continue
            first = next(
                (ln.lstrip("# ").strip() for ln in text.splitlines() if ln.startswith("#")),
                name,
            )
            md.write_text(
                f"---\nname: {name}\ndescription: >-\n  "
                f"{'大爱仙尊' if is_oss_layout() else '测绘引擎'}·{first}\n---\n\n{text}",
                encoding="utf-8",
            )
            print(f"[+] frontmatter {name}")
    print(
        f"doctor store={cat['count']} orphan_store={pruned} "
        f"cursor={len(rows)} fail={len(fail)} fix={int(fix)}"
    )
    return 1 if fail and not fix else 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description=("大爱仙尊" if is_oss_layout() else "SurveyEngine")
        + " skill catalog / validator"
    )
    ap.add_argument("cmd", choices=("list", "validate", "export", "store", "doctor"))
    ap.add_argument("--fix", action="store_true", help="doctor：补缺 frontmatter、清商店孤儿目录")
    ap.add_argument("--json", dest="json_out", default="")
    ap.add_argument("--md", dest="md_out", default="")
    ap.add_argument(
        "--clear-entry",
        action="store_true",
        help="export 时同时写 清晰入口/技能总目录.md 等",
    )
    ap.add_argument("--only", default="", help="只处理这一张目录名")
    ap.add_argument("--search", default="", help="store 子命令：按名字/描述/来源检索")
    ap.add_argument("--limit", type=int, default=30)
    args = ap.parse_args()

    if args.cmd == "doctor":
        return doctor(fix=args.fix)

    if args.cmd == "store":
        cat = STORE / "catalog.json"
        if not cat.is_file():
            print("[!] 先跑 python3 tools/ops/skill_store_sync.py", file=sys.stderr)
            return 2
        data = json.loads(cat.read_text(encoding="utf-8"))
        skills = data.get("skills", [])
        q = (args.search or args.only or "").lower()
        if q:
            skills = [
                s
                for s in skills
                if q in (s.get("name") or "").lower()
                or q in (s.get("description") or "").lower()
                or q in (s.get("source") or "").lower()
                or q in (s.get("id") or "").lower()
            ]
        print(f"store_total={data.get('count')} hit={len(skills)}")
        for s in skills[: args.limit]:
            print(f"{s['id']:56} {s.get('source','')}")
            desc = (s.get("description") or "")[:100]
            if desc:
                print(f"  {desc}")
        if len(skills) > args.limit:
            print(f"... +{len(skills) - args.limit} more")
        return 0

    rows = iter_skills()
    if args.only:
        rows = [r for r in rows if r["name"] == args.only]
        if not rows:
            print(f"[!] not found: {args.only}", file=sys.stderr)
            return 2

    if args.cmd == "list":
        _print_table(rows)
        return 0

    if args.cmd == "validate":
        bad = 0
        for r in rows:
            mark = "OK" if r["valid"] else "FAIL"
            if not r["valid"] or r["warnings"]:
                print(f"[{mark}] {r['name']}")
                for e in r["errors"]:
                    print(f"  error: {e}")
                for w in r["warnings"]:
                    print(f"  warn:  {w}")
            if not r["valid"]:
                bad += 1
        thin = sum(1 for r in rows if r["grade"] == "thin")
        print(f"--- validated={len(rows)} fail={bad} thin={thin}")
        return 1 if bad else 0

    # export
    payload = {
        "source": "daaixianzun" if is_oss_layout() else "surveyengine",
        "skills_dir": "杀招" if is_oss_layout() else ".cursor/skills",
        "count": len(rows),
        "skills": [
            {
                "name": r["name"],
                "description": r["description"],
                "grade": r["grade"],
                "playbooks": r["playbooks"],
                "tools": r["tools"],
                "stub": r["stub"],
                "valid": r["valid"],
            }
            for r in rows
        ],
    }
    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(f"[+] json -> {args.json_out}")
    if args.md_out:
        Path(args.md_out).write_text(_to_md(rows), encoding="utf-8")
        print(f"[+] md -> {args.md_out}")
    if args.clear_entry:
        write_clear_entry_indexes(rows, ROOT / "清晰入口")
    if not args.json_out and not args.md_out and not args.clear_entry:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
