#!/usr/bin/env python3
"""把 skill-main / awesome-agent-skills 里缺的技能全文灌进 智道藏书/skill-store/。

不扫 站点详情/、exports/。大媒体（mp4/gif>1.5MB）跳过。
不写进 杀招/（避免冲掉打站路由）。
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STORE = ROOT / "docs" / "learning" / "skill-store"
SKIP_EXT = {".mp4", ".mov", ".mkv", ".webm", ".mp3", ".wav", ".zip", ".gif"}
MAX_FILE = 1_500_000
UA = "大爱仙尊-skill-store-sync/1.0"

OFFICIAL_REPOS = [
    "anthropics/skills",
    "trailofbits/skills",
    "vercel-labs/agent-skills",
    "vercel-labs/next-skills",
    "cloudflare/skills",
    "huggingface/skills",
    "getsentry/skills",
    "expo/skills",
    "stripe/ai",
    "supabase/agent-skills",
    "better-auth/skills",
    "google-labs-code/stitch-skills",
    "fal-ai-community/skills",
    "remotion-dev/skills",
    "sanity-io/agent-toolkit",
    "tinybirdco/tinybird-agent-skills",
    "neondatabase/agent-skills",
    "microsoft/skills",
    "openai/skills",
    "google/skills",
    "googleworkspace/cli",
    "LambdaTest/agent-skills",
    "NVIDIA/skills",
    "angular/skills",
    "obra/superpowers",
    "WordPress/skills",
    "hashicorp/skills",
    "netlify/skills",
    "firebase/skills",
    "flutter/skills",
    "auth0/skills",
    "apollographql/skills",
    "brave/skills",
    "MiniMax-AI/skills",
    "coinbase/skills",
    "datadog-labs/skills",
    "greensock/skills",
    "makenotion/skills",
    "figma/skills",
    "binance/skills",
    "browserbase/skills",
    "mongodb/skills",
    "clickhouse/skills",
    "duckdb/skills",
    "addyosmani/skills",
    "firecrawl/skills",
    "google-gemini/skills",
    "callstackincubator/agent-skills",
]


def _http_get(url: str, dest: Path, timeout: int = 90) -> bool:
    # 本机 Python 3.14 校验证书会失败，走 curl（与系统钥匙串一致）
    dest.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "curl",
        "-fsSL",
        "--max-time",
        str(timeout),
        "-A",
        UA,
        "-o",
        str(dest),
        url,
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True)
        return r.returncode == 0 and dest.is_file() and dest.stat().st_size > 200
    except Exception:
        return False


def _download_repo(repo: str, work: Path) -> Path | None:
    owner, name = repo.split("/", 1)
    for branch in ("main", "master"):
        url = f"https://codeload.github.com/{owner}/{name}/tar.gz/refs/heads/{branch}"
        tgz = work / f"{owner}__{name}__{branch}.tgz"
        if _http_get(url, tgz):
            out = work / f"{owner}__{name}"
            out.mkdir(exist_ok=True)
            try:
                with tarfile.open(tgz, "r:gz") as tf:
                    tf.extractall(out, filter="data")
            except TypeError:
                with tarfile.open(tgz, "r:gz") as tf:
                    tf.extractall(out)
            tgz.unlink(missing_ok=True)
            return out
        tgz.unlink(missing_ok=True)
    return None


def _find_skill_mds(root: Path) -> list[Path]:
    out = []
    for p in root.rglob("SKILL.md"):
        if "/.git/" in str(p) or "/node_modules/" in str(p):
            continue
        out.append(p)
    return out


def _safe_copy_tree(src_dir: Path, dest_dir: Path) -> int:
    dest_dir.mkdir(parents=True, exist_ok=True)
    n = 0
    for f in src_dir.rglob("*"):
        if not f.is_file():
            continue
        if f.suffix.lower() in SKIP_EXT:
            continue
        if f.stat().st_size > MAX_FILE:
            continue
        rel = f.relative_to(src_dir)
        if any(part.startswith(".") and part not in {".", ".."} for part in rel.parts):
            if rel.parts[0] not in {".cursor"}:
                continue
        target = dest_dir / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(f, target)
        n += 1
    return n


def _slug(owner: str, repo: str, skill: str) -> str:
    # 大爱仙尊目录只用技能名，溯源写 catalog.source
    raw = skill or f"{owner}-{repo}"
    return re.sub(r"[^a-zA-Z0-9._-]+", "-", raw).strip("-")[:120]


def _fm_desc(text: str) -> str:
    m = re.search(r"(?ms)^description:\s*>-?\s*\n((?:[ \t]+.*\n)+)", text)
    if m:
        return " ".join(ln.strip() for ln in m.group(1).splitlines() if ln.strip())[:400]
    m = re.search(r"(?m)^description:\s*(.+)$", text)
    return (m.group(1).strip().strip("'\"") if m else "")[:400]


def _existing_business() -> set[str]:
    d = ROOT / "杀招"
    if not d.is_dir():
        return set()
    return {p.name.lower() for p in d.iterdir() if p.is_dir()}


def ingest_dir(src_root: Path, owner: str, repo: str, dest_skills: Path, seen: set[str]) -> list[dict]:
    recs = []
    for md in _find_skill_mds(src_root):
        skill_dir = md.parent
        name = skill_dir.name
        if name.lower() in {"template", "_template", "example"}:
            continue
        key = f"{owner}/{repo}/{name}".lower()
        if key in seen:
            continue
        seen.add(key)
        slug = _slug(owner, repo, name)
        dest = dest_skills / slug
        copied = _safe_copy_tree(skill_dir, dest)
        if copied == 0:
            continue
        text = (dest / "SKILL.md").read_text(encoding="utf-8", errors="replace") if (dest / "SKILL.md").is_file() else ""
        recs.append(
            {
                "id": slug,
                "name": name,
                "source": f"{owner}/{repo}",
                "description": _fm_desc(text),
                "files": copied,
                "overlap_business": name.lower() in _existing_business(),
            }
        )
    return recs


def copy_local_zip(dest_skills: Path, seen: set[str]) -> list[dict]:
    local = Path("/tmp/skill-main-study/skill-main/skills")
    if not local.is_dir():
        return []
    return ingest_dir(local, "skill-store", "local", dest_skills, seen)


def repos_from_files() -> list[str]:
    found: list[str] = list(OFFICIAL_REPOS)
    sj = Path("/tmp/skill-main-study/skill-main/data/skills.json")
    if sj.is_file():
        data = json.loads(sj.read_text())
        for s in data.get("skills", data if isinstance(data, list) else []):
            link = s.get("link", "")
            m = re.search(r"github.com/([^/]+/[^/]+)", link)
            if m:
                found.append(m.group(1))
    awesome = Path(
        "/Users/sancai/.cursor/projects/Users-sancai-Desktop/agent-tools/"
        "308ddb83-41fd-4952-b48b-93c315681f26.txt"
    )
    if awesome.is_file():
        t = awesome.read_text(encoding="utf-8", errors="replace")
        found.extend(re.findall(r"github.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)", t))
    # 去重保序
    out, seen = [], set()
    for r in found:
        r = r.strip().rstrip(".git")
        if r.lower() in seen or r.count("/") != 1:
            continue
        seen.add(r.lower())
        out.append(r)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-repos", type=int, default=0, help="0=全部")
    ap.add_argument("--sleep", type=float, default=0.4)
    args = ap.parse_args()

    dest_skills = STORE / "skills"
    dest_skills.mkdir(parents=True, exist_ok=True)
    seen: set[str] = set()
    records: list[dict] = []
    cat_path = STORE / "catalog.json"
    if cat_path.is_file():
        old = json.loads(cat_path.read_text(encoding="utf-8"))
        for s in old.get("skills", []):
            src = (s.get("source") or "").lower()
            name = (s.get("name") or "").lower()
            if src and name:
                seen.add(f"{src}/{name}")
            records.append(s)
        print(f"[*] resume catalog {len(records)}")

    print("[*] ingest local skill-main skills/")
    records.extend(copy_local_zip(dest_skills, seen))
    print(f"    local+extracted so far {len(records)}")

    repos = repos_from_files()
    if args.max_repos:
        repos = repos[: args.max_repos]
    print(f"[*] clone {len(repos)} github repos")

    work = Path(tempfile.mkdtemp(prefix="skill-store-fetch-"))
    ok = fail = 0
    try:
        for i, repo in enumerate(repos, 1):
            print(f"  [{i}/{len(repos)}] {repo}", flush=True)
            if any(k.startswith(repo.lower() + "/") for k in seen):
                print("      skip (already in catalog)")
                continue
            extracted = _download_repo(repo, work)
            if not extracted:
                fail += 1
                time.sleep(args.sleep)
                continue
            ok += 1
            owner, name = repo.split("/", 1)
            before = len(records)
            records.extend(ingest_dir(extracted, owner, name, dest_skills, seen))
            print(f"      +{len(records) - before} skills (total {len(records)})")
            shutil.rmtree(extracted, ignore_errors=True)
            time.sleep(args.sleep)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    catalog = {
        "generated_by": "skill_store_sync.py",
        "count": len(records),
        "repos_ok": ok,
        "repos_fail": fail,
        "skills": sorted(records, key=lambda x: x["id"].lower()),
    }
    (STORE / "catalog.json").write_text(
        json.dumps(catalog, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    lines = [
        "# 大爱仙尊通用技能全文仓",
        "",
        f"共 **{len(records)}** 张。目录名是技能 slug，溯源只在 catalog。",
        "",
        "打站仍走 `杀招/`。检索：`skill_catalog.py store`。",
        "",
        f"- 仓库成功 {ok} / 失败 {fail}",
        "",
        "| name | source | description |",
        "|------|--------|-------------|",
    ]
    for r in catalog["skills"]:
        desc = (r.get("description") or "").replace("|", "\\|")[:80]
        lines.append(f"| `{r['name']}` | {r['source']} | {desc} |")
    (STORE / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[+] store={STORE} skills={len(records)} ok={ok} fail={fail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
