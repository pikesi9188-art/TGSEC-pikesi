#!/usr/bin/env python3
"""大爱仙尊 × AutoCVE 流水线封装。

模式:
  status    — 上游目录 / Docker / API 健康
  knowledge — 把 AutoCVE 能力摘要落到案卷（无需 Docker）
  api-ping  — 探测本机 AutoCVE API
  sync      — 登录后拉取 /vulnerabilities 等到案卷（需已启动全栈）
  openapi   — 下载本机 openapi.json 到案卷

上游: https://github.com/larlarua/AutoCVE （AGPL-3.0，致谢 DeepAudit）
钉扎: v1.0.5（install_upstream / ac_start --prod）

授权: 仅审计本地/已授权导入的源码；远程打点仍走 scope。
"""
from __future__ import annotations

import argparse
import json
import shutil
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
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
from typing import Any

ROOT = Path(__file__).resolve().parents[1]  # tools/autocve
ENGINE = ROOT.parents[1]
UPSTREAM = ROOT / "upstream"
KNOWLEDGE = ROOT / "knowledge"
CASES = (ENGINE / "案卷" if (ENGINE / "案卷").is_dir() else ENGINE / "exports" / "bot-recovery")
DEFAULT_API = "http://127.0.0.1:8000"
PIN = "v1.0.5"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def case_out(case: str) -> Path:
    d = CASES / case / "测绘" / "autocve"
    d.mkdir(parents=True, exist_ok=True)
    return d


def http(
    url: str,
    *,
    method: str = "GET",
    headers: dict | None = None,
    data: bytes | None = None,
    timeout: int = 20,
) -> dict[str, Any]:
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()[:5_000_000]
            text = raw.decode("utf-8", "replace")
            try:
                j = json.loads(text) if text else None
            except Exception:
                j = None
            return {"status": r.status, "json": j, "body": text, "error": None}
    except urllib.error.HTTPError as e:
        raw = e.read()[:500_000] if e.fp else b""
        text = raw.decode("utf-8", "replace")
        try:
            j = json.loads(text) if text else None
        except Exception:
            j = None
        return {"status": e.code, "json": j, "body": text, "error": f"HTTP {e.code}"}
    except Exception as e:
        return {"status": 0, "json": None, "body": "", "error": str(e)}


def cmd_status(_: argparse.Namespace) -> int:
    docker = shutil.which("docker")
    up_ok = (UPSTREAM / "docker-compose.yml").is_file() or (UPSTREAM / "README.md").is_file()
    health = http(f"{DEFAULT_API}/health")
    info = {
        "ts": _now(),
        "pin": PIN,
        "upstream_path": str(UPSTREAM),
        "upstream_present": up_ok,
        "docker": bool(docker),
        "api_health": {"status": health.get("status"), "body": health.get("json") or health.get("body"), "error": health.get("error")},
        "ui": "http://localhost:3000",
        "swagger": "http://localhost:8000/docs",
        "install": "bash tools/autocve/bin/install_upstream.sh",
        "start": "bash tools/autocve/bin/ac_start.sh",
        "vs_deepaudit": "DeepAudit=通用白盒/SAST；AutoCVE=CVE挖掘专用 Multi-Agent（Finding+报告）",
    }
    print(json.dumps(info, ensure_ascii=False, indent=2))
    if not docker:
        print("[hint] 无 Docker → 用 knowledge；有 Docker → ac_start.sh")
    if health.get("status") == 200:
        print("[ok] AutoCVE API 已就绪")
        return 0
    return 0


def cmd_knowledge(args: argparse.Namespace) -> int:
    out = case_out(args.case)
    summary = {
        "ts": _now(),
        "source": "https://github.com/larlarua/AutoCVE",
        "license": "AGPL-3.0",
        "pin": PIN,
        "credits": "工程参考 DeepAudit；本引擎已有 tools/deepaudit",
        "agents": [
            "Orchestrator",
            "Recon",
            "Scan",
            "Triage",
            "Finding（CVE 核心）",
            "Verification",
            "Merge/Finalize",
        ],
        "modes": {
            "增强扫描": "Scan → Triage（快滤误报）",
            "智能审计": "Finding（深挖 CVE/0day）",
            "综合审计": "Scan+Triage+Finding",
        },
        "skill_library": [
            "agents/*",
            "code-audit-finding",
            "code-security",
            "cve-report-writer",
            "secknowledge-skill",
        ],
        "local_ports": {
            "ui": 3000,
            "api": 8000,
            "adminer": 8080,
        },
        "workflow": [
            "配置 LLM 模型",
            "导入 Git/本地项目（授权源码）",
            "创建 Agent 审计任务（选模式）",
            "跟踪 ReAct / Agent Tree",
            "漏洞管理 + CVE 报告导出",
            "python3 tools/autocve/bin/ac_pipeline.py sync --case …",
        ],
        "when_to_use": [
            "有本地/授权开源仓库，目标是挖可申报 CVE",
            "DeepAudit SAST 不够深，需要 Finding Agent",
            "需要结构化 CVE 报告模板",
        ],
        "when_not": [
            "线上黑盒（走 scope + 业务 Skill/Playbook）",
            "发卡假支付 / 共享货上游 / Spring Gateway（专用链优先）",
        ],
        "demo_login_hint": "见上游 README / Swagger；常见 demo 账号以实际部署为准",
        "knowledge_files": sorted(p.name for p in KNOWLEDGE.glob("*.md")),
    }
    path = out / "KNOWLEDGE.md"
    lines = [
        "# AutoCVE × 案卷知识摘要",
        "",
        f"- 时间: {summary['ts']}",
        f"- 上游: {summary['source']} （钉扎 {PIN}）",
        f"- License: {summary['license']}",
        "",
        "## Agent 链",
        "",
        "```text",
        "Orchestrator → Recon → Scan → Triage",
        "                 ↘ Finding → Verification → Merge",
        "```",
        "",
        "## 三种模式",
        "",
    ]
    for k, v in summary["modes"].items():
        lines.append(f"- **{k}**: {v}")
    lines += [
        "",
        "## 本引擎命令",
        "",
        "```bash",
        "bash tools/autocve/bin/install_upstream.sh",
        "bash tools/autocve/bin/ac_start.sh          # 或 --prod",
        f"python3 tools/autocve/bin/ac_pipeline.py sync --case {args.case} \\",
        "  --user <email> --password <pass>",
        "```",
        "",
        "## 与 DeepAudit",
        "",
        "- DeepAudit: `tools/deepaudit` — 本地 SAST + 通用 Agent",
        "- AutoCVE: `tools/autocve` — **CVE 挖掘专用**（Finding + 报告 + 一键 CVE）",
        "- 可先 `da_pipeline.py sast` 粗扫，再 AutoCVE 智能审计深挖",
        "",
        "## 缓存文档",
        "",
    ]
    for name in summary["knowledge_files"]:
        lines.append(f"- `tools/autocve/knowledge/{name}`")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    (out / "knowledge.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    # 复制精简指针
    for src_name in ("UPSTREAM_README.md", "ARCHITECTURE.md"):
        src = KNOWLEDGE / src_name
        if src.is_file():
            (out / src_name).write_text(
                f"<!-- cached from AutoCVE; see tools/autocve/knowledge/{src_name} -->\n\n"
                + src.read_text(encoding="utf-8", errors="replace")[:80_000],
                encoding="utf-8",
            )
    print(f"[ok] -> {path}")
    return 0


def cmd_api_ping(args: argparse.Namespace) -> int:
    base = args.api.rstrip("/")
    h = http(f"{base}/health")
    root = http(f"{base}/")
    print(json.dumps({"health": h, "root_head": (root.get("body") or "")[:300]}, ensure_ascii=False, indent=2))
    return 0 if h.get("status") == 200 else 2


def login(api: str, user: str, password: str) -> str:
    data = urllib.parse.urlencode({"username": user, "password": password}).encode()
    r = http(
        f"{api.rstrip('/')}/api/v1/auth/login",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=data,
    )
    j = r.get("json") or {}
    token = j.get("access_token") or j.get("token")
    if not token:
        raise SystemExit(f"[login] failed status={r.get('status')} body={(r.get('body') or '')[:300]}")
    return str(token)


def cmd_sync(args: argparse.Namespace) -> int:
    api = args.api.rstrip("/")
    out = case_out(args.case)
    token = args.token or login(api, args.user, args.password)
    hdrs = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    vulns = http(f"{api}/api/v1/vulnerabilities", headers=hdrs)
    projects = http(f"{api}/api/v1/projects", headers=hdrs)
    # 列表接口可能分页
    report = {
        "ts": _now(),
        "api": api,
        "vulnerabilities_status": vulns.get("status"),
        "vulnerabilities": vulns.get("json"),
        "projects_status": projects.get("status"),
        "projects": projects.get("json"),
    }
    if args.task_id:
        findings = http(f"{api}/api/v1/agent-tasks/{args.task_id}/findings", headers=hdrs)
        summary = http(f"{api}/api/v1/agent-tasks/{args.task_id}/summary", headers=hdrs)
        report["task_id"] = args.task_id
        report["findings"] = findings.get("json")
        report["task_summary"] = summary.get("json")

    path = out / "sync.json"
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    # 写可读 STATUS 片段
    n = 0
    payload = vulns.get("json")
    if isinstance(payload, list):
        n = len(payload)
    elif isinstance(payload, dict):
        items = payload.get("items") or payload.get("data") or payload.get("results")
        if isinstance(items, list):
            n = len(items)
    snippet = out / "STATUS_SNIPPET.md"
    snippet.write_text(
        f"## AutoCVE sync ({_now()})\n\n"
        f"- API: `{api}`\n"
        f"- vulnerabilities HTTP: {vulns.get('status')} count≈{n}\n"
        f"- 详情: `测绘/autocve/sync.json`\n"
        f"- UI: http://localhost:3000\n",
        encoding="utf-8",
    )
    print(f"[ok] vulns_status={vulns.get('status')} count≈{n} -> {path}")
    if vulns.get("status") != 200:
        print("[hint] 检查账号或 API；Swagger: http://localhost:8000/docs")
        return 2
    return 0


def cmd_openapi(args: argparse.Namespace) -> int:
    api = args.api.rstrip("/")
    r = http(f"{api}/api/v1/openapi.json")
    out = case_out(args.case) if args.case else ROOT / "knowledge"
    out.mkdir(parents=True, exist_ok=True)
    path = out / "openapi.json"
    if r.get("json") is not None:
        path.write_text(json.dumps(r["json"], ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    else:
        path.write_text(r.get("body") or "", encoding="utf-8")
    print(f"[ok] status={r.get('status')} -> {path}")
    return 0 if r.get("status") == 200 else 2


def main() -> int:
    ap = argparse.ArgumentParser(description="大爱仙尊 × AutoCVE")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("status")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("knowledge")
    p.add_argument("--case", required=True)
    p.set_defaults(func=cmd_knowledge)

    p = sub.add_parser("api-ping")
    p.add_argument("--api", default=DEFAULT_API)
    p.set_defaults(func=cmd_api_ping)

    p = sub.add_parser("sync", help="拉取漏洞管理列表到案卷")
    p.add_argument("--case", required=True)
    p.add_argument("--api", default=DEFAULT_API)
    p.add_argument("--user", default="")
    p.add_argument("--password", default="")
    p.add_argument("--token", default="", help="已有 JWT 时可跳过登录")
    p.add_argument("--task-id", default="", help="可选：同步某 agent-task 的 findings")
    p.set_defaults(func=cmd_sync)

    p = sub.add_parser("openapi")
    p.add_argument("--api", default=DEFAULT_API)
    p.add_argument("--case", default="")
    p.set_defaults(func=cmd_openapi)

    args = ap.parse_args()
    if args.cmd == "sync" and not args.token and not (args.user and args.password):
        raise SystemExit("[sync] 需要 --token 或 --user/--password")
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
