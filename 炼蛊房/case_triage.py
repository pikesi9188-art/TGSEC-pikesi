#!/usr/bin/env python3
"""案卷 A/B/C Triage：初始化模板、改级、写复工条件。

示例:
  python3 炼蛊房/case_triage.py init --case <案卷> --url https://授权站
  python3 炼蛊房/case_triage.py set --case <案卷> --grade B \\
    --resume "完整 USER_SESSION 经 session_import 校验" \\
    --resume "授权 *.授权站"
  python3 炼蛊房/case_triage.py show --case <案卷>
  python3 炼蛊房/case_triage.py set --case <案卷> --status CLOSED --strict
  python3 炼蛊房/case_triage.py migrate-status-names   # 旧案 STATUS.md → STATUS_<案卷>.md + 软链
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, UTC
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
CASES = ENGINE / "案卷"
TEMPLATE = CASES / "_templates" / "TRIAGE.md"
RETROSPECTIVE_TEMPLATE = CASES / "_templates" / "RETROSPECTIVE.md"
PLAYBOOK = "传承/春秋蝉·分案.md"

_OPS = Path(__file__).resolve().parent
if str(_OPS) not in sys.path:
    sys.path.insert(0, str(_OPS))
import object_matrix as _om  # noqa: E402


def _ensure_object_matrix(case: str):
    """开案即落对象矩阵闸，避免专卡成为唯一路径。"""
    return _om.write_matrix(case)


# 停手/结案态：矩阵未闭合只警告；set --strict 才拒绝
_CLOSING_STATUS = frozenset({"PAUSED", "FROZEN", "CLOSED", "DONE"})


def _warn_matrix_if_closing(
    case: str, status: str | None, *, strict: bool = False
) -> int:
    if not status or status.upper() not in _CLOSING_STATUS:
        return 0
    info = _om.summarize_case(case)
    if not info.get("present"):
        print(
            "[!] 缺少 案卷/object_matrix.md：专卡阴性不够结案，先 object_matrix.py init",
            file=sys.stderr,
        )
        return 2 if strict else 0
    if not info.get("blocking"):
        return 0
    nxt = _om.format_next(info.get("next")) or "先勾结案前三禁"
    n = info.get("untested_count") or 0
    bans = info.get("bans_open") or 0
    print(
        f"[!] 对象矩阵未闭合（未测 {n} / 三禁未勾 {bans}）。下一格：{nxt}",
        file=sys.stderr,
    )
    return 2 if strict else 0

# 跳过非案卷目录（根 STATUS 迁移 / board 扫描）
_SKIP_CASE_DIRS = frozenset(
    {"reports", "cards", "_board", "_archive", "_templates", "_autocve_lab_20260805"}
)


def case_dir(case: str) -> Path:
    return CASES / case


def retrospective_path(case: str) -> Path:
    """案卷复盘机器可读真源（不得存放原始敏感证据）。"""
    return case_dir(case) / "retrospective.json"


def _read_json(path: Path, default: dict | None = None) -> dict:
    if not path.is_file():
        return dict(default or {})
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return dict(default or {})


def _append_unique(current: list[str], values: list[str]) -> list[str]:
    out = list(current or [])
    for value in values:
        item = value.strip()
        if item and item not in out:
            out.append(item)
    return out


def _looks_sensitive(value: str) -> bool:
    """拦截常见机密形态，复盘只允许脱敏摘要。"""
    return bool(
        re.search(
            r"(?i)(authorization\s*:|bearer\s+[a-z0-9._-]{12,}|"
            r"(?:token|cookie|password|secret|api[_-]?key|session)\s*[=:]|"
            r"-----begin .*private key-----)",
            value,
        )
    )


def _recommendations(meta: dict, limit: int = 5) -> list[dict]:
    """按手法与脱敏标签匹配历史复盘；只返回摘要，绝不读取原始案卷材料。"""
    wanted = {
        str(x).strip().lower()
        for x in (meta.get("techniques") or []) + (meta.get("tags") or [])
        if str(x).strip()
    }
    if not wanted or not CASES.is_dir():
        return []

    rows: list[dict] = []
    for d in CASES.iterdir():
        if not d.is_dir() or d.name.startswith("_") or d.name == meta.get("case"):
            continue
        item = _read_json(retrospective_path(d.name))
        if not item:
            continue
        tags = {
            str(x).strip().lower()
            for x in (item.get("techniques") or []) + (item.get("tags") or [])
            if str(x).strip()
        }
        matched = sorted(wanted & tags)
        if not matched:
            continue
        rows.append(
            {
                "case": d.name,
                "outcome": item.get("outcome") or "UNKNOWN",
                "matched_tags": matched,
                "score": len(matched),
                "effective_signals": item.get("effective_signals") or [],
                "ineffective_signals": item.get("ineffective_signals") or [],
                "stop_conditions": item.get("stop_conditions") or [],
                "remediation": item.get("remediation") or [],
            }
        )
    rows.sort(key=lambda row: (-row["score"], row["case"]))
    return rows[:limit]


def _print_se_inject_hint() -> None:
    try:
        from scope_lib import is_oss_layout
        if is_oss_layout():
            return
    except Exception:
        pass
    try:
        from se_inject import workspace_injected
        ok = workspace_injected(ENGINE)
    except Exception:
        claude = ENGINE / "CLAUDE.md"
        text = claude.read_text(encoding="utf-8") if claude.is_file() else ""
        mem = ENGINE / ".claude" / "memory" / "engineer-profile.md"
        ok = "SURVEYENGINE-INJECT:START" in text and mem.is_file()
    if ok:
        return
    print("\n## 助手身份未注入")
    print("Claude Code / Codex 会不认本库授权闸。直接：")
    print("python3 炼蛊房/se_inject.py ensure")


def _print_browser_loot_hint(case: str) -> None:
    try:
        from browser_loot_triage import case_has_loot
    except Exception:
        return
    if not case or not case_has_loot(case):
        return
    print("\n## 案卷里有浏览器包")
    print("不要只做关键词分流。直接：")
    print(f"python3 炼蛊房/browser_loot_triage.py from-case --case {case} --url https://<授权域>")
    print("整包 Cookie + 指纹 UA 回放；活会话再 session_import。")


def _print_recommendations(meta: dict, limit: int = 5) -> None:
    rows = _recommendations(meta, limit)
    print("\n## 复盘知识库推荐")
    if not rows:
        print("暂无匹配的已复盘案卷；完成后用 `retrospect init` 写入首条复盘。")
        return
    for row in rows:
        signals = "；".join(row["effective_signals"][:2]) or "—"
        stops = "；".join(row["stop_conditions"][:1]) or "—"
        print(
            f"- {row['case']} [{row['outcome']}] "
            f"匹配={','.join(row['matched_tags'])}；有效信号：{signals}；停止条件：{stops}"
        )


def status_named_path(case: str) -> Path:
    """给人看的带案卷名 STATUS（编辑器标签可区分）。"""
    return case_dir(case) / f"STATUS_{case}.md"


def status_link_path(case: str) -> Path:
    """兼容软链：STATUS.md → STATUS_<案卷>.md（脚本仍可读 STATUS.md）。"""
    return case_dir(case) / "STATUS.md"


def resolve_status_path(d: Path, case: str | None = None) -> Path | None:
    """定位案卷根上真实 STATUS 正文（优先 STATUS_<案卷>.md）。"""
    case = case or d.name
    named = d / f"STATUS_{case}.md"
    link = d / "STATUS.md"
    if named.exists():
        return named
    if link.exists():
        return link
    # 兜底：根上其它 STATUS_*.md（不含子目录）
    alts = sorted(
        p
        for p in d.glob("STATUS_*.md")
        if p.is_file() or p.is_symlink()
    )
    return alts[0] if alts else None


def ensure_status_layout(case: str) -> Path:
    """保证 STATUS_<案卷>.md 为正文、STATUS.md 为相对软链；返回正文路径。"""
    d = case_dir(case)
    d.mkdir(parents=True, exist_ok=True)
    named = status_named_path(case)
    link = status_link_path(case)

    # 旧布局：仅有普通文件 STATUS.md
    if link.exists() and not link.is_symlink() and not named.exists():
        link.rename(named)
    elif link.exists() and not link.is_symlink() and named.exists():
        # 双份正文：保留带名文件，旧 STATUS.md 挪走
        bak = d / "STATUS.md.dup_before_named"
        if not bak.exists():
            link.rename(bak)
        else:
            link.unlink()

    # 仅有软链指向别处 / 破链：拆掉后重建
    if link.is_symlink():
        try:
            target = link.resolve()
        except OSError:
            target = None
        if not named.exists() and target and target.is_file() and target.parent == d:
            # 软链指向同目录其它文件名时，改名为标准名
            if target.name != named.name:
                target.rename(named)
        if link.exists() or link.is_symlink():
            link.unlink()

    if link.exists() and not link.is_symlink():
        # 仍残留普通文件且 named 已存在
        link.unlink()

    if not link.exists():
        link.symlink_to(named.name)

    return named


def cmd_init(args: argparse.Namespace) -> int:
    d = case_dir(args.case)
    d.mkdir(parents=True, exist_ok=True)
    (d / "测绘").mkdir(exist_ok=True)
    (d / "接管").mkdir(exist_ok=True)

    if not TEMPLATE.is_file():
        print(f"[!] 缺少模板 {TEMPLATE}", file=sys.stderr)
        return 2

    text = TEMPLATE.read_text(encoding="utf-8")
    text = text.replace("`<站>_<日期>`", args.case)
    if args.url:
        text = text.replace("- 入口：", f"- 入口：{args.url}", 1)
    text = text.replace(
        "- 填写时间：",
        f"- 填写时间：{datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}",
        1,
    )
    if args.grade:
        g = args.grade.upper()
        text = re.sub(
            r"\*\*主级：A / B / C\*\*（只圈一个）",
            f"**主级：{g}**",
            text,
        )

    out = d / "TRIAGE.md"
    if out.exists() and not args.force:
        print(f"[!] 已存在 {out}，加 --force 覆盖")
        return 1
    out.write_text(text, encoding="utf-8")

    # 轻量 JSON 供脚本读取
    meta = {
        "case": args.case,
        "url": args.url or "",
        "grade": (args.grade or "").upper() or None,
        "status": "ACTIVE",
        "resume": [],
        "techniques": [],
        "updated_at": datetime.now(UTC).isoformat(),
        "playbook": PLAYBOOK,
    }
    (d / "triage.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")

    # STATUS_<案卷>.md 正文 + STATUS.md 软链
    status = ensure_status_layout(args.case)
    if not status.exists() or status.stat().st_size == 0:
        status.write_text(
            f"# {args.case} — STATUS\n\n"
            f"- 入口：{args.url or ''}\n"
            f"- **Triage**：见 `TRIAGE.md` / `triage.json`（真源 `{PLAYBOOK}`）\n"
            f"- **当前状态：ACTIVE**\n\n"
            f"## Triage\n\n"
            f"- 主级：{(args.grade or '未定').upper()}\n"
            f"- 复工条件：见 TRIAGE.md\n",
            encoding="utf-8",
        )
        print(f"[+] 新建 {status.name} + STATUS.md → {status.name}")
    else:
        print(f"[*] 已有 {status.name}，请手动同步 Triage 小节（或用 set --sync-status）")

    print(f"[+] {out}")
    print(f"[+] {d / 'triage.json'}")
    try:
        mp = _ensure_object_matrix(args.case)
        print(f"[+] {mp}")
    except Exception as exc:
        print(f"[*] 对象矩阵未写入: {exc}")
    _print_recommendations(meta)
    _print_browser_loot_hint(args.case)
    _print_se_inject_hint()
    return 0


def load_meta(case: str) -> dict:
    p = case_dir(case) / "triage.json"
    if p.is_file():
        return json.loads(p.read_text(encoding="utf-8"))
    return {
        "case": case,
        "grade": None,
        "status": None,
        "resume": [],
        "techniques": [],
        "playbook": PLAYBOOK,
    }


def save_meta(case: str, meta: dict) -> None:
    meta["updated_at"] = datetime.now(UTC).isoformat()
    path = case_dir(case) / "triage.json"
    path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")


def sync_status(case: str, meta: dict) -> None:
    status = ensure_status_layout(case)
    block = (
        "## Triage\n\n"
        f"- 主级：**{meta.get('grade') or '未定'}**\n"
        f"- 进攻状态：{meta.get('status') or '—'}\n"
        f"- 复工条件：\n"
        + (
            "\n".join(f"  - [ ] {r}" for r in meta.get("resume") or [])
            or "  - （无）"
        )
        + "\n"
        f"- 手法：{', '.join(meta.get('techniques') or []) or '见 TRIAGE.md'}\n"
        f"- 详表：`TRIAGE.md` · 索引：`{PLAYBOOK}`\n"
    )
    if not status.exists():
        status.write_text(
            f"# {case} — STATUS\n\n{block}\n",
            encoding="utf-8",
        )
        return
    text = status.read_text(encoding="utf-8")
    if re.search(r"^## Triage\s*$", text, re.M):
        text = re.sub(
            r"^## Triage\s*\n(?:.*\n)*?(?=^## |\Z)",
            block + "\n",
            text,
            count=1,
            flags=re.M,
        )
    else:
        # 插到首个 ## 之前或文末
        m = re.search(r"^## ", text, re.M)
        if m:
            text = text[: m.start()] + block + "\n" + text[m.start() :]
        else:
            text = text.rstrip() + "\n\n" + block
    status.write_text(text, encoding="utf-8")


def cmd_set(args: argparse.Namespace) -> int:
    d = case_dir(args.case)
    if not d.is_dir():
        print(f"[!] 案卷不存在: {d}（先 init）", file=sys.stderr)
        return 2
    meta = load_meta(args.case)
    if args.grade:
        g = args.grade.upper()
        if g not in {"A", "B", "C"}:
            print("[!] grade 必须是 A/B/C", file=sys.stderr)
            return 2
        meta["grade"] = g
    if args.status:
        meta["status"] = args.status.upper()
    if args.clear_resume:
        meta["resume"] = []
    if args.resume:
        # 追加去重（在 clear 之后，便于 --clear-resume --resume … 重置）
        cur = list(meta.get("resume") or [])
        for r in args.resume:
            if r not in cur:
                cur.append(r)
        meta["resume"] = cur
    if args.technique:
        cur = list(meta.get("techniques") or [])
        for t in args.technique:
            if t not in cur:
                cur.append(t)
        meta["techniques"] = cur

    save_meta(args.case, meta)
    blocked = _warn_matrix_if_closing(
        args.case, meta.get("status"), strict=bool(getattr(args, "strict", False))
    )

    # 更新 TRIAGE.md 主级行（若存在）
    triage = d / "TRIAGE.md"
    if triage.is_file() and meta.get("grade"):
        t = triage.read_text(encoding="utf-8")
        t2 = re.sub(
            r"\*\*主级：.*?\*\*",
            f"**主级：{meta['grade']}**",
            t,
            count=1,
        )
        if meta.get("status"):
            t2 = re.sub(
                r"进攻状态：.*",
                f"进攻状态：{meta['status']}",
                t2,
                count=1,
            )
        if meta.get("resume"):
            # 替换复工条件列表块（简单策略：找到章节后重写到下一 ##）
            resume_block = (
                "## 复工条件（B/C 必填；全满足才允许从 FROZEN/PAUSED 拉回 ACTIVE）\n\n"
                + "\n".join(f"- [ ] {r}" for r in meta["resume"])
                + "\n"
            )
            if re.search(r"^## 复工条件", t2, re.M):
                t2 = re.sub(
                    r"^## 复工条件.*?\n(?:.*\n)*?(?=^## |\Z)",
                    resume_block + "\n",
                    t2,
                    count=1,
                    flags=re.M,
                )
        triage.write_text(t2, encoding="utf-8")

    if args.sync_status or True:
        sync_status(args.case, meta)

    print(json.dumps(meta, ensure_ascii=False, indent=2))
    return blocked


def cmd_retrospect_init(args: argparse.Namespace) -> int:
    """从脱敏模板建立复盘 Markdown 和机器可读条目。"""
    d = case_dir(args.case)
    if not d.is_dir():
        print(f"[!] 案卷不存在: {d}", file=sys.stderr)
        return 2
    if not RETROSPECTIVE_TEMPLATE.is_file():
        print(f"[!] 缺少模板 {RETROSPECTIVE_TEMPLATE}", file=sys.stderr)
        return 2

    meta = load_meta(args.case)
    path = retrospective_path(args.case)
    if path.exists() and not args.force:
        print(f"[!] 已存在 {path}，加 --force 覆盖", file=sys.stderr)
        return 1
    outcome = args.outcome.upper()
    if outcome not in {"SUCCESS", "PARTIAL", "FAILED", "PAUSED"}:
        print("[!] outcome 必须是 SUCCESS/PARTIAL/FAILED/PAUSED", file=sys.stderr)
        return 2
    entry = {
        "schema_version": 1,
        "case": args.case,
        "outcome": outcome,
        "techniques": list(meta.get("techniques") or []),
        "tags": [],
        "prerequisites": [],
        "effective_signals": [],
        "ineffective_signals": [],
        "stop_conditions": [],
        "remediation": [],
        "evidence_refs": [],
        "updated_at": datetime.now(UTC).isoformat(),
    }
    path.write_text(json.dumps(entry, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    markdown = d / "RETROSPECTIVE.md"
    if not markdown.exists() or args.force:
        text = RETROSPECTIVE_TEMPLATE.read_text(encoding="utf-8")
        text = text.replace("`<站>_<日期>`", args.case)
        text = text.replace("- 结论：SUCCESS / PARTIAL / FAILED / PAUSED", f"- 结论：{outcome}")
        text = text.replace(
            "- 复盘时间：",
            f"- 复盘时间：{datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}",
        )
        if entry["techniques"]:
            text = text.replace("- 使用手法：", f"- 使用手法：{', '.join(entry['techniques'])}")
        markdown.write_text(text, encoding="utf-8")
    print(f"[+] {path}")
    print(f"[+] {markdown}")
    return 0


def cmd_retrospect_set(args: argparse.Namespace) -> int:
    """填充复盘 JSON；value 只接受脱敏摘要。"""
    path = retrospective_path(args.case)
    entry = _read_json(path)
    if not entry:
        print(f"[!] 缺少 {path}（先 retrospect init）", file=sys.stderr)
        return 2
    fields = {
        "tag": "tags",
        "prerequisite": "prerequisites",
        "effective_signal": "effective_signals",
        "ineffective_signal": "ineffective_signals",
        "stop_condition": "stop_conditions",
        "remediation": "remediation",
        "evidence_ref": "evidence_refs",
    }
    for arg_name, field in fields.items():
        values = getattr(args, arg_name) or []
        if any(_looks_sensitive(value) for value in values):
            print(f"[!] {arg_name} 包含疑似机密；请改为脱敏摘要或相对证据路径", file=sys.stderr)
            return 2
        entry[field] = _append_unique(entry.get(field) or [], values)
    if args.outcome:
        outcome = args.outcome.upper()
        if outcome not in {"SUCCESS", "PARTIAL", "FAILED", "PAUSED"}:
            print("[!] outcome 必须是 SUCCESS/PARTIAL/FAILED/PAUSED", file=sys.stderr)
            return 2
        entry["outcome"] = outcome
    entry["updated_at"] = datetime.now(UTC).isoformat()
    path.write_text(json.dumps(entry, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(entry, ensure_ascii=False, indent=2))
    return 0


def cmd_recommend(args: argparse.Namespace) -> int:
    meta = load_meta(args.case)
    if not meta.get("case"):
        meta["case"] = args.case
    meta["tags"] = args.tag or []
    rows = _recommendations(meta, args.limit)
    if args.format == "json":
        print(json.dumps(rows, ensure_ascii=False, indent=2))
    else:
        _print_recommendations(meta, args.limit)
    _print_browser_loot_hint(args.case)
    _print_se_inject_hint()
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    meta = load_meta(args.case)
    print(json.dumps(meta, ensure_ascii=False, indent=2))
    triage = case_dir(args.case) / "TRIAGE.md"
    print(f"TRIAGE.md: {'OK' if triage.is_file() else 'MISSING'} {triage}")
    info = _om.summarize_case(args.case)
    if not info.get("present"):
        print(f"object_matrix.md: MISSING {info.get('path')}")
    else:
        nxt = _om.format_next(info.get("next")) or "-"
        print(
            f"object_matrix.md: untested={info['untested_count']} "
            f"bans_open={info['bans_open']} next={nxt}"
        )
    _print_browser_loot_hint(args.case)
    _print_se_inject_hint()
    return 0


def _infer_from_status(case: str) -> dict:
    """无 triage.json 时从 STATUS 猜级（弱推断）。"""
    status = resolve_status_path(case_dir(case), case)
    meta = {
        "case": case,
        "grade": None,
        "status": None,
        "resume": [],
        "techniques": [],
        "url": "",
        "inferred": True,
    }
    if status is None or not status.exists():
        return meta
    text = status.read_text(encoding="utf-8", errors="replace")
    m = re.search(r"主级[：:]\s*\*?\*?([ABC])", text)
    if m:
        meta["grade"] = m.group(1)
    if re.search(r"PAUSED|暂停", text, re.I):
        meta["status"] = "PAUSED"
    elif re.search(r"FROZEN|冷冻", text, re.I):
        meta["status"] = "FROZEN"
    elif re.search(r"ACTIVE|推进中", text, re.I):
        meta["status"] = "ACTIVE"
    for line in re.findall(r"^\s*-\s*\[[ xX]\]\s*(.+)$", text, re.M):
        meta["resume"].append(line.strip())
    um = re.search(r"https?://[^\s\)\]>]+", text)
    if um:
        meta["url"] = um.group(0)
    return meta


def cmd_board(args: argparse.Namespace) -> int:
    rows: list[dict] = []
    if not CASES.is_dir():
        print(f"[!] 无案卷目录 {CASES}", file=sys.stderr)
        return 2
    for d in sorted(CASES.iterdir()):
        if not d.is_dir() or d.name.startswith("_"):
            continue
        tj = d / "triage.json"
        if tj.is_file():
            try:
                meta = json.loads(tj.read_text(encoding="utf-8"))
            except Exception:
                meta = {"case": d.name, "grade": "?", "status": "?"}
            meta.setdefault("case", d.name)
            meta["inferred"] = False
        elif args.include_inferred and resolve_status_path(d) is not None:
            meta = _infer_from_status(d.name)
        else:
            continue
        if args.grade and (meta.get("grade") or "").upper() != args.grade.upper():
            continue
        if args.status and (meta.get("status") or "").upper() != args.status.upper():
            continue
        rows.append(meta)

    for m in rows:
        info = _om.summarize_case(m.get("case") or "")
        m["matrix_present"] = bool(info.get("present"))
        m["matrix_untested"] = info.get("untested_count")
        m["matrix_bans_open"] = info.get("bans_open")
        m["matrix_next"] = _om.format_next(info.get("next")) if info.get("present") else None

    # 排序：A → B → C → 空；同级 ACTIVE 优先
    order = {"A": 0, "B": 1, "C": 2}
    st_order = {"ACTIVE": 0, "PAUSED": 1, "FROZEN": 2}

    def sort_key(m: dict):
        return (
            order.get((m.get("grade") or "").upper(), 9),
            st_order.get((m.get("status") or "").upper(), 9),
            m.get("case") or "",
        )

    rows.sort(key=sort_key)

    if args.format == "json":
        text = json.dumps(rows, ensure_ascii=False, indent=2)
    elif args.format == "csv":
        import csv
        import io

        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(
            [
                "case",
                "grade",
                "status",
                "url",
                "resume",
                "techniques",
                "inferred",
                "matrix_untested",
            ]
        )
        for m in rows:
            w.writerow(
                [
                    m.get("case"),
                    m.get("grade"),
                    m.get("status"),
                    m.get("url"),
                    " | ".join(m.get("resume") or []),
                    ",".join(m.get("techniques") or []),
                    m.get("inferred"),
                    m.get("matrix_untested"),
                ]
            )
        text = buf.getvalue()
    else:
        lines = [
            f"# Triage Board ({datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')})",
            "",
            f"共 **{len(rows)}** 案 · 真源 `{PLAYBOOK}`",
            "",
            "| 级 | 状态 | 案卷 | 矩阵未测 | 复工条件数 | 手法 |",
            "|----|------|------|----------|------------|------|",
        ]
        for m in rows:
            g = m.get("grade") or "?"
            st = m.get("status") or "?"
            n = len(m.get("resume") or [])
            tech = ", ".join(m.get("techniques") or [])[:40]
            inf = "≈" if m.get("inferred") else ""
            mx = m.get("matrix_untested")
            mx_s = "—" if mx is None else str(mx)
            lines.append(
                f"| {g}{inf} | {st} | `{m.get('case')}` | {mx_s} | {n} | {tech} |"
            )
        # 摘要
        from collections import Counter

        gc = Counter((m.get("grade") or "?") for m in rows)
        lines += [
            "",
            "## 汇总",
            "",
            f"- A: {gc.get('A', 0)} · B: {gc.get('B', 0)} · C: {gc.get('C', 0)} · 未定: {gc.get('?', 0) + gc.get(None, 0)}",
            "- 建议：同时 ACTIVE 的 A ≤ 2；C/B 无复工条件满足前勿空转",
            "- 矩阵未测：空格子数（— = 尚未落表）；有身份应先填 `案卷/object_matrix.md`",
            "",
        ]
        text = "\n".join(lines)

    out = Path(args.out) if args.out else (CASES / "_board" / "TRIAGE_BOARD.md")
    if args.format == "json":
        out = out if str(out).endswith(".json") else out.with_suffix(".json")
    elif args.format == "csv":
        out = out if str(out).endswith(".csv") else out.with_suffix(".csv")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")
    print(text if args.print else f"[+] {out} ({len(rows)} rows)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="案卷 A/B/C Triage")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init", help="从模板创建 TRIAGE.md")
    p.add_argument("--case", required=True)
    p.add_argument("--url", default="")
    p.add_argument("--grade", default="")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("set", help="设置等级/复工条件")
    p.add_argument("--case", required=True)
    p.add_argument("--grade", default="")
    p.add_argument("--status", default="", help="ACTIVE|PAUSED|FROZEN|CLOSED|DONE")
    p.add_argument("--resume", action="append", default=[], help="可重复")
    p.add_argument("--clear-resume", action="store_true")
    p.add_argument("--technique", action="append", default=[])
    p.add_argument("--sync-status", action="store_true", default=True)
    p.add_argument(
        "--strict",
        action="store_true",
        help="停手/结案且矩阵未闭合则 exit 2",
    )
    p.set_defaults(func=cmd_set)

    p = sub.add_parser("show", help="显示 triage.json")
    p.add_argument("--case", required=True)
    p.set_defaults(func=cmd_show)

    p = sub.add_parser("retrospect", help="建立或更新脱敏复盘知识条目")
    retrospect_sub = p.add_subparsers(dest="retrospect_cmd", required=True)
    p_init = retrospect_sub.add_parser("init", help="为已有案卷创建复盘模板与 JSON")
    p_init.add_argument("--case", required=True)
    p_init.add_argument("--outcome", default="PAUSED", help="SUCCESS|PARTIAL|FAILED|PAUSED")
    p_init.add_argument("--force", action="store_true")
    p_init.set_defaults(func=cmd_retrospect_init)
    p_set = retrospect_sub.add_parser("set", help="追加脱敏复盘字段")
    p_set.add_argument("--case", required=True)
    p_set.add_argument("--outcome", default="")
    p_set.add_argument("--tag", action="append", default=[])
    p_set.add_argument("--prerequisite", action="append", default=[])
    p_set.add_argument("--effective-signal", dest="effective_signal", action="append", default=[])
    p_set.add_argument("--ineffective-signal", dest="ineffective_signal", action="append", default=[])
    p_set.add_argument("--stop-condition", dest="stop_condition", action="append", default=[])
    p_set.add_argument("--remediation", action="append", default=[])
    p_set.add_argument("--evidence-ref", dest="evidence_ref", action="append", default=[])
    p_set.set_defaults(func=cmd_retrospect_set)

    p = sub.add_parser("recommend", help="按当前 Triage 标签推荐已复盘案卷")
    p.add_argument("--case", required=True)
    p.add_argument("--tag", action="append", default=[], help="补充匹配标签，可重复")
    p.add_argument("--limit", type=int, default=5)
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.set_defaults(func=cmd_recommend)

    p = sub.add_parser("board", help="批量 A/B/C 看板")
    p.add_argument("--format", choices=["md", "json", "csv"], default="md")
    p.add_argument("--out", default="", help="默认 案卷/_board/TRIAGE_BOARD.md")
    p.add_argument("--grade", default="", help="过滤 A/B/C")
    p.add_argument("--status", default="", help="过滤 ACTIVE/PAUSED/FROZEN")
    p.add_argument("--include-inferred", action="store_true", help="无 triage.json 时从 STATUS 弱推断")
    p.add_argument("--print", action="store_true", help="同时打印到 stdout")
    p.set_defaults(func=cmd_board)

    p = sub.add_parser(
        "migrate-status-names",
        help="案卷根 STATUS.md → STATUS_<案卷>.md + STATUS.md 软链（不动子目录）",
    )
    p.add_argument("--dry-run", action="store_true", help="只打印不改")
    p.set_defaults(func=cmd_migrate_status_names)

    args = ap.parse_args()
    return int(args.func(args) or 0)


def cmd_migrate_status_names(args: argparse.Namespace) -> int:
    """批量：根目录普通 STATUS.md 改名为 STATUS_<案卷>.md，并留 STATUS.md 软链。"""
    if not CASES.is_dir():
        print(f"[!] 无案卷目录 {CASES}", file=sys.stderr)
        return 2

    migrated = skipped = already = errors = 0
    for d in sorted(CASES.iterdir()):
        if not d.is_dir() or d.name.startswith("_") or d.name in _SKIP_CASE_DIRS:
            continue
        case = d.name
        named = d / f"STATUS_{case}.md"
        link = d / "STATUS.md"

        try:
            # 已是目标布局
            if (
                named.exists()
                and link.is_symlink()
                and link.readlink().name == named.name
            ):
                already += 1
                continue

            has_plain = link.exists() and not link.is_symlink()
            has_named = named.exists()
            if not has_plain and not has_named:
                skipped += 1
                continue

            if args.dry_run:
                action = []
                if has_plain and not has_named:
                    action.append(f"rename STATUS.md -> {named.name}")
                elif has_plain and has_named:
                    action.append("park STATUS.md as .dup_before_named")
                if not (link.is_symlink() and has_named):
                    action.append(f"symlink STATUS.md -> {named.name}")
                print(f"[dry] {case}: {'; '.join(action)}")
                migrated += 1
                continue

            ensure_status_layout(case)
            # 空 named（仅建了软链）且无正文：不算成功迁移
            if named.exists() and named.stat().st_size >= 0:
                print(f"[+] {case}: {named.name} + STATUS.md -> {named.name}")
                migrated += 1
            else:
                skipped += 1
        except OSError as e:
            print(f"[!] {case}: {e}", file=sys.stderr)
            errors += 1

    print(
        f"\nDone: migrated={migrated} already={already} "
        f"skipped_no_status={skipped} errors={errors}"
        + (" (dry-run)" if args.dry_run else "")
    )
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
