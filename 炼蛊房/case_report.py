#!/usr/bin/env python3
"""案卷报告汇编：从 STATUS + 矩阵/测绘 JSON 生成 Mermaid 链路与初稿报告。

示例:
  python3 炼蛊房/case_report.py --case <案卷>
  python3 炼蛊房/case_report.py --case <案卷> --publish-draft
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

ENGINE = Path(__file__).resolve().parents[1]
CASES = ENGINE / "案卷"
REPORTS = CASES / "reports"


def load_json(path: Path) -> Any:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def read_text(path: Path, limit: int = 200_000) -> str:
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")[:limit]


def collect(case: str) -> dict[str, Any]:
    root = CASES / case
    recon = root / "测绘"
    takeover = root / "接管"
    status_path = root / f"STATUS_{case}.md"
    if not status_path.exists():
        status_path = root / "STATUS.md"
    artifacts: dict[str, Any] = {
        "case": case,
        "root": str(root),
        "status_md": read_text(status_path),
        "triage_md": read_text(root / "TRIAGE.md"),
        "triage": load_json(root / "triage.json") or {},
        "files": {},
    }

    # 矩阵类
    for name, path in [
        ("callback_matrix", recon / "callback_matrix.json"),
        ("pay_matrix", recon / "pay_matrix" / "forge_matrix.json"),
        ("trade_probe", recon / "trade_probe.json"),
        ("origin", recon / "origin.json"),
        ("scope_expand", recon / "scope_expand.json"),
        ("acg_probe", recon / "acg" / "acg_probe.json"),
        ("payment_hint", recon / "deepaudit" / "payment_hint.json"),
        ("auto_deepaudit", recon / "deepaudit" / "auto_trigger.json"),
        ("member_probe", takeover / "session" / "member_probe.json"),
        ("pipeline", takeover / "session" / "pipeline_report.json"),
        ("cf_consume", takeover / "session" / "cf_consume.json"),
        ("verdict", root / "VERDICT.json"),
    ]:
        data = load_json(path)
        if data is not None:
            artifacts["files"][name] = {"path": str(path.relative_to(ENGINE)), "data": data}

    # 最新 forge_matrix_* 若 forge_matrix.json 不存在
    pm_dir = recon / "pay_matrix"
    if "pay_matrix" not in artifacts["files"] and pm_dir.is_dir():
        stamped = sorted(pm_dir.glob("forge_matrix_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        if stamped:
            data = load_json(stamped[0])
            if data is not None:
                artifacts["files"]["pay_matrix"] = {
                    "path": str(stamped[0].relative_to(ENGINE)),
                    "data": data,
                }

    return artifacts


def infer_url(art: dict) -> str:
    t = art.get("triage") or {}
    if t.get("url"):
        return t["url"]
    m = re.search(r"https?://[^\s\)\]>`\"']+", art.get("status_md") or "")
    return m.group(0) if m else ""


def infer_verdict(art: dict) -> str:
    status = (art.get("triage") or {}).get("status") or ""
    md = art.get("status_md") or ""
    if re.search(r"SUCCESS|已出卡|COMPLETED|接管成功", md, re.I):
        return "SUCCESS"
    if re.search(r"PARTIAL|部分成功", md, re.I):
        return "PARTIAL"
    if status.upper() in {"PAUSED", "FROZEN"} or re.search(r"PAUSED|暂停|冷冻", md, re.I):
        return "STOPPED"
    if re.search(r"sign error|验签硬化|未入账", md, re.I):
        return "NOT_CLOSED"
    return "NOT_CLOSED"


def matrix_summary(art: dict) -> dict[str, Any]:
    out: dict[str, Any] = {"sources": [], "interesting": [], "total": 0, "handles": set(), "dry_run": False}
    for key in ("pay_matrix", "callback_matrix"):
        block = (art.get("files") or {}).get(key)
        if not block:
            continue
        data = block["data"]
        rows = data.get("results") if isinstance(data, dict) else data
        if not isinstance(rows, list):
            continue
        out["sources"].append(block["path"])
        for r in rows:
            out["total"] += 1
            if r.get("handle"):
                out["handles"].add(str(r["handle"]))
            resp = r.get("resp") or {}
            if resp.get("dry_run"):
                out["dry_run"] = True
            interesting = r.get("interesting")
            body = (resp.get("body") or "") if isinstance(resp, dict) else ""
            if interesting is None:
                interesting = bool(body) and "sign error" not in body.lower() and "dry_run" not in str(resp)
            if interesting:
                out["interesting"].append(
                    {
                        "handle": r.get("handle"),
                        "variant": r.get("variant") or r.get("name"),
                        "body": body[:120],
                        "source": key,
                    }
                )
    out["handles"] = sorted(out["handles"])
    return out


def extract_pay_url(art: dict) -> str:
    pm = (art.get("files") or {}).get("pay_matrix", {}).get("data") or {}
    if isinstance(pm, dict) and pm.get("pay_url"):
        return pm["pay_url"]
    tp = (art.get("files") or {}).get("trade_probe", {}).get("data")
    if isinstance(tp, dict):
        # trade_probe 可能是 {s,t} 包一层
        t = tp.get("t") or tp
        if isinstance(t, str):
            try:
                t = json.loads(t)
            except Exception:
                t = {}
        if isinstance(t, dict):
            data = t.get("data") or t
            if isinstance(data, dict) and data.get("url"):
                return str(data["url"])
    m = re.search(r"https?://[^\s\"']+/Pay\?[^\s\"']+", art.get("status_md") or "")
    return m.group(0) if m else ""


def mermaid_chain(art: dict, mx: dict, url: str) -> str:
    """生成 flowchart + 可选 timeline。"""
    case = art["case"]
    pay_url = extract_pay_url(art)
    mid_host = ""
    if pay_url:
        m = re.search(r"https?://([^/]+)", pay_url)
        mid_host = m.group(1) if m else ""

    expand = (art.get("files") or {}).get("scope_expand", {}).get("data")
    expanded = False
    if isinstance(expand, list) and expand:
        expanded = any(x.get("changed") for x in expand if isinstance(x, dict))
    elif isinstance(expand, dict):
        expanded = bool(expand.get("changed"))

    origin = (art.get("files") or {}).get("origin", {}).get("data") or {}
    non_cdn = origin.get("non_cdn_candidates") or []

    acg = (art.get("files") or {}).get("acg_probe", {}).get("data") or {}
    cb_alive = [c.get("handle") for c in (acg.get("callback_alive") or []) if c.get("handle")]
    admin_hits = [a.get("path") for a in (acg.get("admin_hits") or [])]

    grade = (art.get("triage") or {}).get("grade") or "?"
    st = (art.get("triage") or {}).get("status") or "?"

    def nid(s: str) -> str:
        return re.sub(r"[^a-zA-Z0-9_]", "_", s)[:40]

    lines = [
        "```mermaid",
        "flowchart TD",
        f"  {nid('A')}[授权开案 {_esc_mermaid(case)}] --> {nid('B')}[Triage {_esc_mermaid(str(grade))}/{_esc_mermaid(str(st))}]",
        f"  {nid('B')} --> C[指纹/测绘<br/>{_esc_mermaid(url or '目标')}]",
    ]
    if mid_host:
        lines.append(f"  C --> D[下单跳转<br/>{_esc_mermaid(mid_host)}]")
        if expanded:
            lines.append(f"  D --> E[静默扩权<br/>{_esc_mermaid(mid_host)}]")
            lines.append("  E --> F[回调矩阵 pay_matrix]")
        else:
            lines.append("  D --> F[回调矩阵 pay_matrix]")
    else:
        lines.append("  C --> F[回调矩阵 pay_matrix]")

    handles = mx.get("handles") or []
    if handles:
        lines.append(f"  F --> G[handles: {', '.join(handles[:6])}]")
    else:
        lines.append("  F --> G[callback 探测]")

    resume_anchor = "G"  # 默认 fallback 连接点
    if mx.get("interesting"):
        lines.append("  G --> H{interesting 变体}")
        lines.append("  H -->|有| I[查单/出卡验证]")
        lines.append("  H -->|无| J[验签硬化/换路]")
        resume_anchor = "I"
    elif mx.get("dry_run"):
        lines.append("  G --> K[矩阵 dry-run 未实打]")
        lines.append("  K --> L[复工: 非 dry-run 全矩阵]")
        resume_anchor = "L"
    else:
        lines.append("  G --> J[sign error / 未入账]")
        lines.append("  J --> L[复工条件]")
        resume_anchor = "L"

    if non_cdn:
        lines.append(f"  C --> O[源站候选 {len(non_cdn)}]")
    if cb_alive:
        lines.append(f"  C --> P[ACG callback 存活<br/>{', '.join(cb_alive[:5])}]")
        lines.append("  P --> F")
    if admin_hits:
        lines.append(f"  C --> Q[后台线索<br/>{admin_hits[0]}]")

    sess = (art.get("files") or {}).get("pipeline") or (art.get("files") or {}).get("cf_consume")
    if sess:
        alive = (sess.get("data") or {}).get("session_alive") or (sess.get("data") or {}).get("usable")
        lines.append(f"  C --> S[会话流水线 alive={bool(alive)}]")

    # resume
    resume = (art.get("triage") or {}).get("resume") or []
    if resume:
        lines.append(f"  {resume_anchor} --> R[复工条件]")
        for i, r in enumerate(resume[:4]):
            lines.append(f"  R --> R{i}[{_esc_mermaid(r)[:50]}]")

    lines.append("```")
    return "\n".join(lines)


def _esc_mermaid(s: str) -> str:
    return s.replace('"', "'").replace("[", "(").replace("]", ")").replace("\n", " ")


def mermaid_timeline(art: dict) -> str:
    """用 STATUS 勾选与 JSON 时间戳拼简易 timeline。"""
    events: list[tuple[str, str]] = []
    md = art.get("status_md") or ""
    for m in re.finditer(r"^- \[[xX]\] (.+)$", md, re.M):
        events.append(("done", m.group(1).strip()[:60]))
    for m in re.finditer(r"^- \[ \] (.+)$", md, re.M):
        events.append(("todo", m.group(1).strip()[:60]))

    # JSON timestamps
    for key, label in [
        ("scope_expand", "静默扩权"),
        ("pay_matrix", "支付矩阵"),
        ("origin", "源站 recon"),
        ("acg_probe", "ACG 探针"),
    ]:
        block = (art.get("files") or {}).get(key)
        if not block:
            continue
        data = block["data"]
        ts = ""
        if isinstance(data, dict):
            ts = (data.get("generated_at") or "")[:19]
        elif isinstance(data, list) and data and isinstance(data[-1], dict):
            ts = (data[-1].get("generated_at") or "")[:19]
        events.append(("evt", f"{label} {ts}".strip()))

    if not events:
        return ""

    lines = ["```mermaid", "timeline"]
    lines.append(f"    title {art['case']} 作业时间线")
    # mermaid timeline: section + : event
    lines.append("    section 进展")
    for kind, text in events[:20]:
        prefix = "完成" if kind == "done" else ("待办" if kind == "todo" else "事件")
        lines.append(f"      {prefix} : {_esc_mermaid(text)}")
    lines.append("```")
    return "\n".join(lines)


def build_draft(art: dict) -> tuple[str, dict]:
    url = infer_url(art)
    verdict = infer_verdict(art)
    mx = matrix_summary(art)
    triage = art.get("triage") or {}
    pay_url = extract_pay_url(art)
    chain = mermaid_chain(art, mx, url)
    timeline = mermaid_timeline(art)

    # STATUS 摘要：取前几段非空行
    status_lines = []
    for line in (art.get("status_md") or "").splitlines():
        if line.strip():
            status_lines.append(line.rstrip())
        if len(status_lines) >= 40:
            break

    evidence_rows = []
    for name, block in (art.get("files") or {}).items():
        evidence_rows.append(f"| {name} | `{block['path']}` | 机器产物 | 内部 |")

    interesting_rows = []
    for hit in mx.get("interesting") or []:
        interesting_rows.append(
            f"| {hit.get('handle')} | {hit.get('variant')} | {(hit.get('body') or '')[:80]} |"
        )
    if not interesting_rows:
        interesting_rows.append("| — | — | 无 interesting（或仅 dry-run） |")

    resume = triage.get("resume") or []
    resume_done = triage.get("resume_done") or []
    resume_md = "\n".join(f"- [ ] {r}" for r in resume) or "- （无）"
    if resume_done:
        resume_md += "\n\n已记录完成：\n" + "\n".join(f"- [x] {r}" for r in resume_done)

    techniques = ", ".join(triage.get("techniques") or []) or "见 STATUS"

    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    draft = f"""# {art['case']} — 初稿报告（自动汇编）

> 由 `炼蛊房/case_report.py` 生成于 {now}。**须人工复核**业务影响与结论等级后再归档正式报告。

| 项 | 内容 |
|----|------|
| 目标 | {url or '（见 STATUS）'} |
| 案卷 | `案卷/{art['case']}/` |
| Triage | **{triage.get('grade') or '?'}** / {triage.get('status') or '?'} |
| 建议结论 | `{verdict}` |
| 手法 | {techniques} |
| 支付跳转 | {pay_url or '—'} |

## 一句话结论

（请人工填写）当前建议等级 `{verdict}`：矩阵 interesting={len(mx.get('interesting') or [])}/{mx.get('total') or 0}
{'；矩阵含 dry-run，尚未实打' if mx.get('dry_run') else ''}。

## 攻击链路（Mermaid）

{chain}

## 时间线

{timeline or '_暂无足够时间戳拼 timeline_'}

## 假支付 / 回调矩阵摘要

| handle | variant | body 摘要 |
|--------|---------|-----------|
{chr(10).join(interesting_rows)}

- 矩阵来源: {', '.join(f'`{s}`' for s in mx.get('sources') or []) or '无'}
- handles: {', '.join(mx.get('handles') or []) or '无'}

## 复工条件

{resume_md}

## STATUS 摘录

```markdown
{chr(10).join(status_lines[:35])}
```

## 证据索引

| 证据 | 相对路径 | 能证明什么 | 敏感级别 |
|------|----------|------------|----------|
{chr(10).join(evidence_rows) if evidence_rows else f'| STATUS | `STATUS_{art["case"]}.md` | 过程结论 | 内部 |'}

## 下一次只做

1. 满足复工条件中未勾选项  
2. 非 dry-run 跑通 `pay_matrix` 并查单  
3. 结论升级后：更新 `VERDICT.json` + 正式归档 `案卷/reports/`

## 明确不再做

- 无新证据下重复空签矩阵空转  
- 未过 CF 会话时硬撞 Turnstile  

## 归档提示

| 结论 | 写到 |
|------|------|
| 成功出卡/接管 | `reports/01`～`07` 对应手法 + 桌面分类 |
| 部分成功 | 对应手法报告 + `案卷/呈文/部分成功/` |
| 未闭环 | `reports/08_failed_sites.md` 或过程草稿 |

参见：`大爱仙尊使用/recovery_reports/FOLDER_GUIDE.md` · `智道藏书/kb/templates/STATUS-TEMPLATE.md`
"""

    verdict_obj = {
        "verdict_tier": verdict,
        "target_achieved": verdict == "SUCCESS",
        "case": art["case"],
        "url": url,
        "triage_grade": triage.get("grade"),
        "triage_status": triage.get("status"),
        "primary_playbook": triage.get("playbook") or techniques,
        "matrix_interesting": len(mx.get("interesting") or []),
        "matrix_total": mx.get("total") or 0,
        "matrix_dry_run": bool(mx.get("dry_run")),
        "pay_url": pay_url,
        "generated_at": datetime.now(UTC).isoformat(),
        "draft": True,
        "note": "自动汇编初稿，须人工确认后去掉 draft=true",
    }
    return draft, verdict_obj


def write_outputs(case: str, draft: str, verdict: dict, chain_only: str, publish: bool) -> dict[str, str]:
    root = CASES / case
    root.mkdir(parents=True, exist_ok=True)
    paths = {}
    p_draft = root / "DRAFT_REPORT.md"
    p_draft.write_text(draft, encoding="utf-8")
    paths["draft"] = str(p_draft)

    p_chain = root / "CHAIN.mmd"
    # strip fences for .mmd raw
    raw = chain_only
    if raw.startswith("```mermaid"):
        raw = raw.split("\n", 1)[1]
    if raw.endswith("```"):
        raw = raw.rsplit("```", 1)[0]
    p_chain.write_text(raw.strip() + "\n", encoding="utf-8")
    paths["chain"] = str(p_chain)

    p_verdict = root / "VERDICT.json"
    # 不覆盖非 draft 的正式 VERDICT
    existing = load_json(p_verdict)
    if existing and not existing.get("draft", True) and existing.get("verdict_tier"):
        paths["verdict"] = str(p_verdict) + " (kept formal)"
    else:
        p_verdict.write_text(json.dumps(verdict, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        paths["verdict"] = str(p_verdict)

    # 汇编索引
    idx = {
        "case": case,
        "generated_at": verdict.get("generated_at"),
        "draft_report": "DRAFT_REPORT.md",
        "chain": "CHAIN.mmd",
        "verdict": "VERDICT.json",
    }
    p_idx = root / "REPORT_BUNDLE.json"
    p_idx.write_text(json.dumps(idx, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    paths["bundle"] = str(p_idx)

    if publish:
        dest_dir = REPORTS / "drafts"
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / f"{case}_DRAFT.md"
        dest.write_text(draft, encoding="utf-8")
        paths["published"] = str(dest)

    return paths


def main() -> int:
    ap = argparse.ArgumentParser(description="案卷报告汇编")
    ap.add_argument("--case", required=True)
    ap.add_argument("--publish-draft", action="store_true", help="复制到 案卷/reports/drafts/")
    ap.add_argument("--print", action="store_true", help="打印报告到 stdout")
    args = ap.parse_args()

    root = CASES / args.case
    if not root.is_dir():
        print(f"[!] 案卷不存在: {root}", file=sys.stderr)
        return 2

    art = collect(args.case)
    draft, verdict = build_draft(art)
    # build_draft 内已生成 chain；从 draft 文本中提取 mermaid flowchart 块，
    # 避免重复计算 matrix_summary / mermaid_chain / infer_url。
    chain_match = re.search(r"(```mermaid\nflowchart TD\b.*?```)", draft, re.S)
    chain = chain_match.group(1) if chain_match else ""
    paths = write_outputs(args.case, draft, verdict, chain, args.publish_draft)

    print(f"[+] draft   {paths['draft']}")
    print(f"[+] chain   {paths['chain']}")
    print(f"[+] verdict {paths['verdict']}")
    if paths.get("published"):
        print(f"[+] published {paths['published']}")
    print(f"    verdict_tier={verdict['verdict_tier']} matrix={verdict['matrix_interesting']}/{verdict['matrix_total']}")
    if args.print:
        print("\n" + draft[:4000])
    return 0


if __name__ == "__main__":
    sys.exit(main())
