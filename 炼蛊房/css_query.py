#!/usr/bin/env python3
"""查询大爱仙尊内的 CyberSecurity-Skills 分类库。"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
PACK = ENGINE / "智道藏书" / "三十九门"
INDEX = PACK / "index.json"

# 别名 → 检索词（只指路，不生成利用代码）
ALIASES: dict[str, tuple[str, ...]] = {
    "c2": ("metasploit", "远程控制", "cobalt", "empire"),
    "cobalt": ("远程控制", "metasploit"),
    "sliver": ("远程控制", "metasploit"),
    "havoc": ("远程控制", "metasploit"),
    "mimikatz": ("凭证转储", "哈希传递", "凭证窃取"),
    "pth": ("哈希传递", "凭证转储"),
    "pass-the-hash": ("哈希传递", "凭证转储"),
    "dcsync": ("凭证转储", "哈希传递"),
    "lsass": ("凭证转储", "凭证窃取"),
    "键盘记录": ("键盘记录", "屏幕捕获"),
    "keylog": ("键盘记录", "屏幕捕获"),
    "keylogger": ("键盘记录", "屏幕捕获"),
    "amsi": ("amsi", "edr"),
    "edr": ("amsi", "edr", "痕迹"),
    "免杀": ("amsi", "edr", "混淆"),
    "etw": ("amsi", "edr"),
    "unhook": ("amsi", "edr", "进程注入"),
    "芋道": ("芋道",),
    "假支付": ("假支付",),
    "号库": ("号库",),
    "shell目录": ("wp 高熵", "wordpress"),
    "webshell": ("wp 高熵", "wordpress"),
    "wp-includes": ("wp 高熵", "wordpress"),
    "高熵马": ("wp 高熵",),
}


def _data() -> dict:
    if not INDEX.is_file():
        raise SystemExit(f"缺少 {INDEX}")
    return json.loads(INDEX.read_text(encoding="utf-8"))


def resolve_skill_file(mod_path: str, filename: str) -> Path:
    """上游 index 写文件名，落盘在 <模块>/skills/。"""
    name = Path(filename).name
    for p in (
        PACK / mod_path / "skills" / name,
        PACK / mod_path / name,
    ):
        if p.is_file():
            return p
    return PACK / mod_path / "skills" / name


def rel_skill(mod_path: str, filename: str) -> str:
    p = resolve_skill_file(mod_path, filename)
    try:
        return str(p.relative_to(PACK))
    except ValueError:
        return f"{mod_path}/skills/{Path(filename).name}"


def skill_id(mid: int, idx: int) -> str:
    return f"{mid:02d}-{idx:03d}"


def iter_skills(data: dict):
    yield ("00", 1, "大爱仙尊业务", "假支付 / 芋道 / TG 号库", PACK / "00-大爱仙尊业务-大爱仙尊" / "MODULE.md")
    for m in data["modules"]:
        mid = int(m["id"])
        for i, sk in enumerate(m["skills"], 1):
            yield (
                skill_id(mid, i),
                i,
                sk["name"],
                m["name_cn"],
                resolve_skill_file(m["path"], sk["file"]),
            )


def list_modules() -> None:
    d = _data()
    print(f"{d['meta']['title']}  v{d['meta']['version']}  {d['meta']['total_skills']} skills")
    print("00  大爱仙尊业务  大爱仙尊  （假支付/盘口/TG）")
    for m in d["modules"]:
        print(f"{int(m['id']):02d}  {m['name_cn']}  {m['name_en']}  ({m['skill_count']})")


def list_skills(module: str | None) -> None:
    d = _data()
    want = None
    if module is not None:
        want = int(module)
    if want in (None, 0):
        print("00-001  大爱仙尊业务  00-大爱仙尊业务-大爱仙尊/MODULE.md")
        if want == 0:
            return
    for m in d["modules"]:
        mid = int(m["id"])
        if want is not None and mid != want:
            continue
        for i, sk in enumerate(m["skills"], 1):
            print(f"{skill_id(mid, i)}  {sk['name']}  {rel_skill(m['path'], sk['file'])}")


def _needles(kw: str) -> list[str]:
    raw = kw.strip().lower()
    out = [raw]
    for alias, extra in ALIASES.items():
        if raw == alias or raw == alias.replace("-", " "):
            out.extend(extra)
        elif len(raw) >= 2 and (raw in alias or alias in raw):
            out.extend(extra)
    # 去重保序
    seen: set[str] = set()
    uniq: list[str] = []
    for n in out:
        if n and n not in seen:
            seen.add(n)
            uniq.append(n)
    return uniq


def _blob_has(blob: str, needle: str) -> bool:
    if not needle:
        return False
    if needle.isascii() and len(needle) <= 3:
        return re.search(rf"(?<![a-z0-9]){re.escape(needle)}(?![a-z0-9])", blob) is not None
    return needle in blob


def search(kw: str, limit: int = 40) -> None:
    needles = _needles(kw)
    d = _data()
    hits: list[tuple[str, str, str]] = []
    extra = [
        ("00-001", "假支付 / 芋道 TMA / TG 号库", "00-大爱仙尊业务-大爱仙尊/MODULE.md"),
        ("00-002", "WP 高熵 PHP 马落点狩猎", "00-大爱仙尊业务-大爱仙尊/MODULE.md"),
    ]
    for sid, name, path in extra:
        blob = f"{sid} {name} {path}".lower()
        if any(_blob_has(blob, n) for n in needles):
            hits.append((sid, name, path))
    for m in d["modules"]:
        mid = int(m["id"])
        for i, sk in enumerate(m["skills"], 1):
            rel = rel_skill(m["path"], sk["file"])
            blob = f"{sk['name']} {sk['file']} {m['name_cn']} {m.get('name_en','')} {rel}".lower()
            if any(_blob_has(blob, n) for n in needles):
                hits.append((skill_id(mid, i), sk["name"], rel))
    if not hits:
        print("无命中")
        return
    shown = hits[: max(1, limit)]
    for sid, name, path in shown:
        print(f"{sid}  {name}  智道藏书/三十九门/{path}")
    if len(hits) > len(shown):
        print(f"... 还有 {len(hits) - len(shown)} 条，加大 --limit")


def get_skill(sid: str, full: bool = False) -> None:
    token = sid.strip().replace("_", "-")
    # 允许直接丢中文名
    if not (len(token) >= 4 and token[:2].isdigit() and "-" in token):
        d = _data()
        kw = token.lower()
        for m in d["modules"]:
            for i, sk in enumerate(m["skills"], 1):
                if kw in sk["name"].lower() or kw in sk["file"].lower():
                    token = skill_id(int(m["id"]), i)
                    break
            else:
                continue
            break
        else:
            if "假支付" in sid or "芋道" in sid or "号库" in sid:
                token = "00-001"
            else:
                raise SystemExit(f"找不到技能：{sid}（用 search --keyword 或 id 如 05-002）")

    parts = token.split("-")
    if len(parts) < 2 or not parts[0].isdigit() or not parts[1].isdigit():
        raise SystemExit("id 形如 05-002")
    mid, idx = int(parts[0]), int(parts[1])
    if mid == 0:
        p = PACK / "00-大爱仙尊业务-大爱仙尊" / "MODULE.md"
        if not p.is_file():
            raise SystemExit(f"缺少 {p}")
        print(f"# 00-001 大爱仙尊业务\n# {p}\n")
        print(p.read_text(encoding="utf-8"))
        return
    d = _data()
    try:
        mod = next(m for m in d["modules"] if int(m["id"]) == mid)
    except StopIteration:
        raise SystemExit(f"没有模块 {mid:02d}") from None
    skills = mod["skills"]
    if idx < 1 or idx > len(skills):
        raise SystemExit(f"{mid:02d} 只有 {len(skills)} 张，没有 {skill_id(mid, idx)}")
    sk = skills[idx - 1]
    p = resolve_skill_file(mod["path"], sk["file"])
    if not p.is_file():
        raise SystemExit(f"文件不存在：{p}")
    text = p.read_text(encoding="utf-8")
    print(f"# {skill_id(mid, idx)}  {sk['name']}\n# {p}\n")
    if full or len(text) <= 12000:
        print(text)
    else:
        print(text[:12000])
        print(f"\n... 已截断，全文 {len(text)} 字。加 --full 看完整。")


def doctor() -> int:
    d = _data()
    missing: list[str] = []
    ok = 0
    for m in d["modules"]:
        for sk in m["skills"]:
            p = resolve_skill_file(m["path"], sk["file"])
            if p.is_file():
                ok += 1
            else:
                missing.append(f"{m['path']}/skills/{sk['file']}")
    declared = int(d["meta"]["total_skills"])
    print(f"resolved {ok}/{declared}")
    if missing:
        print("missing:")
        for x in missing[:20]:
            print(f"  {x}")
        return 1
    if ok != declared:
        print(f"count mismatch: files={ok} meta={declared}")
        return 1
    # 回归：旧根路径不应再被当成真源
    stale = PACK / "05-后渗透-PostExploitation" / "凭证转储与哈希传递-CredentialDumpingPtH.md"
    if stale.is_file():
        print(f"unexpected root copy: {stale}")
        return 1
    print("ok")
    return 0


def main() -> None:
    ap = argparse.ArgumentParser(description="CyberSecurity-Skills 分类查询")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list-modules")
    ls = sub.add_parser("list-skills")
    ls.add_argument("--module", help="模块号，如 05 或 0")
    p = sub.add_parser("search")
    p.add_argument("--keyword", required=True)
    p.add_argument("--limit", type=int, default=40)
    g = sub.add_parser("get")
    g.add_argument("--id", required=True, help="如 05-002，或中文名")
    g.add_argument("--full", action="store_true")
    sub.add_parser("doctor")
    args = ap.parse_args()
    if args.cmd == "list-modules":
        list_modules()
    elif args.cmd == "list-skills":
        list_skills(args.module)
    elif args.cmd == "search":
        search(args.keyword, args.limit)
    elif args.cmd == "get":
        get_skill(args.id, full=args.full)
    else:
        sys.exit(doctor())


if __name__ == "__main__":
    main()
