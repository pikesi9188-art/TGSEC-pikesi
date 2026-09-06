#!/usr/bin/env python3
"""大爱仙尊逆向路由：hint → 本库专卡。只指路，不生成利用代码。

真源：同目录 reverse_routing.json（改规则只改那一份）。
专链（假支付 / 芋道 / Shop / Gateway / Doris / IMDS）优先于通用 RE。
不要和 AGENTS 决策树抢入口。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

OPS = Path(__file__).resolve().parent
ROOT = (OPS.parent if (OPS.parent / "杀招").is_dir() else (OPS.parent if (OPS.parent / "杀招").is_dir() else OPS.parents[1]))
ROUTING_PATH = OPS / "reverse_routing.json"
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))

GENERIC = {"reverse-engineering"}


def load_routing(path: Path | None = None) -> dict[str, Any]:
    p = path or ROUTING_PATH
    data = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(data.get("routes"), dict) or not data.get("priority"):
        raise ValueError(f"无效路由表: {p}")
    return data


def _compact(s: str) -> str:
    return "".join(s.lower().split())


def _haystacks(hint: str) -> tuple[str, str]:
    text = hint.strip().lower()
    return text, _compact(text)


def _needle_in(needle: str, text: str, compact: str, *, word: bool = False) -> bool:
    n = needle.lower()
    if word:
        return re.search(rf"(?<![a-z0-9]){re.escape(n.strip())}(?![a-z0-9])", text) is not None
    if n in text:
        return True
    cn = _compact(n)
    return bool(cn) and cn in compact


def _group_hit(text: str, compact: str, group: dict[str, Any]) -> str | None:
    any_keys = [str(k) for k in (group.get("any") or [])]
    must_all = [str(k) for k in (group.get("mustAll") or [])]
    exclude = [str(k) for k in (group.get("exclude") or [])]
    word = bool(group.get("word"))
    matched: str | None = None
    if any_keys:
        for k in any_keys:
            if _needle_in(k, text, compact, word=word):
                matched = k
                break
        if matched is None:
            return None
    elif must_all:
        matched = must_all[0]
    else:
        return None
    for k in must_all:
        if not _needle_in(k, text, compact, word=word):
            return None
    for k in exclude:
        if _needle_in(k, text, compact, word=word):
            return None
    return matched


def _route_hit(text: str, compact: str, spec: dict[str, Any]) -> str | None:
    for group in spec.get("keywords") or []:
        if not isinstance(group, dict):
            continue
        hit = _group_hit(text, compact, group)
        if hit:
            return hit
    return None


def _family_of(skill: str, table: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    for name, fam in (table.get("families") or {}).items():
        if skill in (fam.get("members") or []):
            return str(name), fam if isinstance(fam, dict) else {}
    return "", {}


def _hit_record(rid: str, spec: dict[str, Any], matched: str | None, table: dict[str, Any]) -> dict[str, Any]:
    skill = str(spec["skill"])
    fam = str(spec.get("family") or "")
    fam_spec: dict[str, Any] = {}
    if not fam:
        fam, fam_spec = _family_of(skill, table)
    else:
        fam_spec = (table.get("families") or {}).get(fam) or {}
    return {
        "id": rid,
        "skill": skill,
        "matched": matched,
        "note": spec.get("note") or "",
        "playbook": spec.get("playbook") or "",
        "family": fam,
        "next": spec.get("next") or "",
        "family_rule": (fam_spec.get("rule") if isinstance(fam_spec, dict) else "") or "",
    }


def route(hint: str, routing: dict[str, Any] | None = None) -> dict[str, Any]:
    table = routing or load_routing()
    routes: dict[str, Any] = table["routes"]
    priority: list[str] = list(table["priority"])
    fallback_id = str(table.get("meta", {}).get("fallbackId") or "R0")
    text, compact = _haystacks(hint)

    hits: list[dict[str, Any]] = []
    seen: set[str] = set()
    suppress: set[str] = set()

    for alias in table.get("aliases") or []:
        if not isinstance(alias, dict):
            continue
        group = {"any": alias.get("any") or [alias.get("from")]}
        matched = _group_hit(text, compact, group)
        if not matched:
            continue
        dest = str(alias["to"])
        spec = next((s for s in routes.values() if s.get("skill") == dest), None)
        if not isinstance(spec, dict):
            spec = {"skill": dest, "note": f"旧卡 {alias.get('from')} 已并入"}
        rec = _hit_record(f"alias:{alias.get('from')}", spec, matched, table)
        rec["note"] = rec["note"] or f"旧卡 {alias.get('from')} 已并入 {dest}"
        if dest not in seen:
            hits.append(rec)
            seen.add(dest)

    for rid in priority:
        spec = routes.get(rid)
        if not isinstance(spec, dict):
            continue
        matched = _route_hit(text, compact, spec)
        if not matched:
            continue
        skill = str(spec["skill"])
        if skill in seen:
            continue
        hits.append(_hit_record(rid, spec, matched, table))
        seen.add(skill)
        for s in spec.get("suppress") or []:
            suppress.add(str(s))

    if not hits:
        fb = routes.get(fallback_id) or {}
        hits.append(
            _hit_record(
                fallback_id,
                {
                    "skill": str(fb.get("skill") or "reverse-engineering"),
                    "note": "未命中专词，先开总路由再分诊",
                    "family": fb.get("family") or "",
                    "next": fb.get("next") or "",
                },
                None,
                table,
            )
        )

    primary = hits[0]
    fam = primary.get("family") or ""
    nxt = primary.get("next") or ""
    also: list[dict[str, Any]] = []
    for h in hits[1:]:
        if h["skill"] in GENERIC:
            continue
        if h["skill"] in suppress:
            continue
        if nxt and h["skill"] == nxt:
            continue
        if fam and h.get("family") == fam:
            continue
        also.append(h)
    return {"hint": hint, "primary": primary, "also": also}


def coherence(routing: dict[str, Any] | None = None) -> list[str]:
    table = routing or load_routing()
    routes: dict[str, Any] = table["routes"]
    priority = list(table["priority"])
    fallback = str(table.get("meta", {}).get("fallbackId") or "R0")
    errors: list[str] = []
    if fallback not in routes:
        errors.append(f"fallback {fallback} 不在 routes")
    missing_pri = [rid for rid in routes if rid not in priority]
    extra_pri = [rid for rid in priority if rid not in routes]
    if missing_pri:
        errors.append(f"priority 漏了: {', '.join(missing_pri)}")
    if extra_pri:
        errors.append(f"priority 多了: {', '.join(extra_pri)}")
    if len(priority) != len(set(priority)):
        errors.append("priority 有重复 id")
    skills_root = ROOT / "杀招"
    for rid, spec in routes.items():
        skill = str(spec.get("skill") or "")
        if not skill:
            errors.append(f"{rid} 无 skill")
            continue
        if not (skills_root / skill / "SKILL.md").is_file():
            errors.append(f"{rid} → .{skill} 无 SKILL.md")
    known = {str(s.get("skill")) for s in routes.values()}
    families = table.get("families") or {}
    for fname, fam in families.items():
        for m in fam.get("members") or []:
            if not (skills_root / str(m) / "SKILL.md").is_file():
                errors.append(f"family {fname} 成员 {m} 无 SKILL.md")
    for alias in table.get("aliases") or []:
        dest = str(alias.get("to") or "")
        if dest and not (skills_root / dest / "SKILL.md").is_file():
            errors.append(f"alias {alias.get('from')} → {dest} 无 SKILL.md")
    for rid, spec in routes.items():
        fam = spec.get("family")
        if fam and fam not in families:
            errors.append(f"{rid} family={fam} 未登记")
        nxt = spec.get("next")
        if nxt and not (skills_root / str(nxt) / "SKILL.md").is_file():
            errors.append(f"{rid} next={nxt} 无 SKILL.md")
    for i, case in enumerate(table.get("cases") or []):
        primary = str(case.get("primary") or "")
        if primary not in known:
            errors.append(f"cases[{i}] primary={primary} 不是已登记 skill")
    return errors


def run_cases(routing: dict[str, Any] | None = None) -> list[str]:
    table = routing or load_routing()
    fails: list[str] = []
    for case in table.get("cases") or []:
        hint = str(case["hint"])
        expect = str(case["primary"])
        forbid = [str(x) for x in (case.get("forbid") or [])]
        data = route(hint, table)
        got = data["primary"]["skill"]
        also = {h["skill"] for h in data["also"]}
        if got != expect:
            fails.append(f"{hint!r} primary={got} expect={expect}")
        for bad in forbid:
            if got == bad or bad in also:
                fails.append(f"{hint!r} 不应露出 {bad}")
    return fails


def check_target(target: str) -> dict[str, Any]:
    from scope_lib import host_of, in_scope

    host = host_of(target)
    ok = bool(host) and in_scope(target)
    return {
        "target": target,
        "host": host,
        "in_scope": ok,
        "grant": (
            f"python3 炼蛊房/scope_expand.py --grant {host} --case <案卷> --note '用户授权'"
            if host
            else ""
        ),
    }


def _print_human(data: dict[str, Any], scope: dict[str, Any] | None = None) -> None:
    p = data["primary"]
    print(f"PRIMARY  {p['skill']}")
    print(f"  id:      {p.get('id') or '-'}")
    print(f"  matched: {p['matched'] or '-'}")
    print(f"  note:    {p['note']}")
    print(f"  skill:   杀招/{p['skill']}/SKILL.md")
    if p.get("playbook"):
        print(f"  playbook: {p['playbook']}")
    else:
        print("  playbook: 传承/逆骨·认族.md")
    if p.get("family") or p.get("next"):
        print(f"FAMILY  {p.get('family') or '-'}")
        if p.get("next"):
            print(f"  next:   {p['next']}  （同族交接，不要并行开）")
        if p.get("family_rule"):
            print(f"  rule:   {p['family_rule']}")
    if data["also"]:
        print("ALSO")
        for h in data["also"]:
            print(f"  - {h['skill']}  ({h['matched']})")
    if scope is not None:
        print("SCOPE")
        print(f"  host: {scope.get('host') or '-'}")
        print(f"  in_scope: {scope['in_scope']}")
        if not scope["in_scope"]:
            print("  ACT: 禁止（先 --grant）")
            if scope.get("grant"):
                print(f"  next: {scope['grant']}")
        else:
            print("  ACT: 允许（授权内按 PRIMARY 打开专卡）")


def _print_list(routing: dict[str, Any]) -> None:
    for rid in routing["priority"]:
        spec = routing["routes"][rid]
        print(f"{rid:6}  {spec['skill']:36}  {spec.get('label') or ''}")


def main() -> int:
    ap = argparse.ArgumentParser(description="大爱仙尊逆向任务 → 本库专卡")
    ap.add_argument("--hint", default="", help="用户原话 / 文件类型 / 工具名")
    ap.add_argument("--target", default="", help="可选 URL/域名：ACT 前走 scope 闸")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--coherence", action="store_true")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()

    table = load_routing()

    if args.coherence or args.self_test:
        errs = coherence(table)
        if args.self_test:
            errs.extend(run_cases(table))
        if errs:
            for e in errs:
                print(f"FAIL {e}")
            return 1
        n = len(table.get("cases") or [])
        print(f"self-test ok  {n} cases  {len(table['routes'])} routes")
        return 0

    if args.list:
        _print_list(table)
        return 0

    if not args.hint:
        ap.error("需要 --hint 或 --self-test / --coherence / --list")

    data = route(args.hint, table)
    scope = check_target(args.target) if args.target else None
    if args.json:
        out = dict(data)
        if scope is not None:
            out["scope"] = scope
        json.dump(out, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
    else:
        _print_human(data, scope)
    if scope is not None and not scope["in_scope"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
