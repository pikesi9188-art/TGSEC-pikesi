#!/usr/bin/env python3
"""1day / nuclei / exploitarium 作业入口（授权闸门）。

示例:
  python3 tools/1day-kit/od_kit.py doctor
  python3 tools/1day-kit/od_kit.py learn
  python3 tools/1day-kit/od_kit.py version
  python3 tools/1day-kit/od_kit.py explain --id spring-actuator-unauth
  python3 tools/1day-kit/od_kit.py list-templates --q actuator
  python3 tools/1day-kit/od_kit.py validate
  python3 tools/1day-kit/od_kit.py index
  python3 tools/1day-kit/od_kit.py search --q redis
  python3 tools/1day-kit/od_kit.py update-templates
  python3 tools/1day-kit/od_kit.py nuclei --url https://授权站 --case <案卷> [--tags cve,rce] [--custom-only]
  python3 tools/1day-kit/od_kit.py cvebase trending
  python3 tools/1day-kit/od_kit.py cvebase lookup --cve CVE-2026-72898 --docs
  python3 tools/1day-kit/od_kit.py cvebase search --q "Metabase SQL" --limit 5
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import re
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
from typing import Any, Iterator

OPS = _kit_ops_dir(Path(__file__))
ENGINE = Path(__file__).resolve().parents[2]
EXPLOITARIUM = ENGINE / "poc-db" / "exploitarium"
ARSENAL_BIN = ENGINE / "tools" / "arsenal" / "bin"
CVEBASE_BASE = os.environ.get("CVEBASE_BASE", "https://cvebase.io").rstrip("/")
CUSTOM_TEMPLATES = Path(__file__).resolve().parent / "custom-templates"

if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))

from scope_lib import host_of, in_scope  # noqa: E402


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def case_dir(case: str) -> Path:
    d = (ENGINE / "案卷" if (ENGINE / "案卷").is_dir() else ENGINE / "exports" / "bot-recovery") / case / "测绘" / "1day"
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


_MACHO = (b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe")
_ELF = b"\x7fELF"
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _is_native_binary(path: Path) -> bool:
    """当前 OS 能跑的二进制才算。Darwin 收 Mach-O，Linux 收 ELF。"""
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
    except OSError:
        return False
    sysname = platform.system()
    if sysname == "Darwin":
        return magic in _MACHO
    if sysname == "Linux":
        return magic == _ELF
    return True


def find_nuclei() -> str | None:
    """PATH → arsenal/bin → arsenal/linux；按本机 OS 过滤架构。"""
    cands: list[Path] = []
    which = shutil.which("nuclei")
    if which:
        cands.append(Path(which))
    cands.append(ARSENAL_BIN / "nuclei")
    cands.append(ENGINE / "tools" / "arsenal" / "linux" / "nuclei")
    for p in cands:
        if not p or not p.is_file() or not os.access(p, os.X_OK):
            continue
        if not _is_native_binary(p):
            continue
        return str(p)
    return None


def _plain(text: str) -> str:
    return _ANSI.sub("", text or "")


def _nuclei_version_line(out: str) -> str:
    for ln in _plain(out).splitlines():
        if "Nuclei Engine Version" in ln:
            return re.sub(r"^\[(?:INF|WRN|ERR|VER)\]\s*", "", ln.strip())
    stripped = _plain(out).strip()
    return stripped.splitlines()[0] if stripped else ""


def resolve_template_arg(raw: str) -> Path:
    """相对仓库根、custom-templates 文件名、绝对路径。"""
    p = Path(raw).expanduser()
    cands = [p]
    if not p.is_absolute():
        cands.append(ENGINE / raw)
        cands.append(CUSTOM_TEMPLATES / Path(raw).name)
    for c in cands:
        try:
            r = c.resolve()
        except OSError:
            continue
        if r.exists():
            return r
    raise SystemExit(f"[err] 模板不存在: {raw}")


def _run_nuclei(args: list[str], timeout: int | None = 30) -> tuple[int, str]:
    nuc = find_nuclei()
    if not nuc:
        return 1, ""
    cmd = [nuc, *args]
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, "[timeout]"
    except OSError as e:
        return 1, str(e)


def templates_dir() -> Path:
    env = os.environ.get("NUCLEI_TEMPLATES")
    if env:
        return Path(env).expanduser()
    # 默认落在大爱仙尊目录（gitignore），不写 ~/ 也不进 tools/vendor
    return ENGINE / "tools" / "1day-kit" / "nuclei-templates"


def build_index() -> list[dict]:
    items: list[dict] = []
    if not EXPLOITARIUM.is_dir():
        return items
    for child in sorted(EXPLOITARIUM.iterdir()):
        if not child.is_dir() or child.name.startswith("."):
            continue
        readme = child / "README.md"
        summary = ""
        if readme.is_file():
            try:
                summary = readme.read_text(encoding="utf-8", errors="ignore")[:400].replace("\n", " ")
            except OSError:
                pass
        items.append(
            {
                "id": child.name,
                "path": str(child.relative_to(ENGINE)),
                "summary": summary,
                "tags": [t for t in child.name.replace("_", "-").split("-") if t],
            }
        )
    return items


def _count_yaml(root: Path) -> int:
    if not root.is_dir():
        return 0
    return sum(1 for _ in root.rglob("*.yaml"))


def cmd_doctor(_: argparse.Namespace) -> int:
    nuc = find_nuclei()
    print(f"[nuclei] {nuc or 'MISSING — bash scripts/install-arsenal-macos.sh 或 brew install nuclei'}")
    if nuc:
        rc, out = _run_nuclei(["-version", "-duc", "-nc"], timeout=20)
        print(f"[version] {_nuclei_version_line(out) or f'rc={rc}'}")
    td = templates_dir()
    n_yml = _count_yaml(td)
    n_custom = _count_yaml(CUSTOM_TEMPLATES)
    print(f"[templates] {td} yaml≈{n_yml}")
    print(f"[custom] {CUSTOM_TEMPLATES} yaml={n_custom}")
    print(f"[exploitarium] {EXPLOITARIUM} exists={EXPLOITARIUM.is_dir()}")
    idx = build_index()
    print(f"[index] exploitarium entries={len(idx)}")
    print("[handbook] 传承/针匣·手册.md")
    ok = bool(nuc) and n_yml > 0
    print("[ok] 1day-kit ready" if ok else "[warn] nuclei 或 templates 未就绪，可先 update-templates")
    return 0 if nuc else 1


def cmd_index(args: argparse.Namespace) -> int:
    items = build_index()
    out = ENGINE / "tools" / "1day-kit" / "exploitarium_index.json"
    payload = {"ts": _now(), "count": len(items), "items": items}
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"[ok] wrote {out} count={len(items)}")
    if args.case:
        c = case_dir(args.case) / "exploitarium_index.json"
        c.write_text(out.read_text(encoding="utf-8"), encoding="utf-8")
        print(f"[ok] case copy {c}")
    return 0


def cmd_search(args: argparse.Namespace) -> int:
    q = (args.q or "").lower().strip()
    items = build_index()
    hits = []
    for it in items:
        blob = (it["id"] + " " + it.get("summary", "")).lower()
        if q in blob or any(q in t for t in it.get("tags") or []):
            hits.append(it)
    print(json.dumps({"q": q, "count": len(hits), "hits": hits}, ensure_ascii=False, indent=2))
    return 0 if hits else 2


def cmd_update_templates(args: argparse.Namespace) -> int:
    nuc = find_nuclei()
    if not nuc:
        raise SystemExit("[err] 找不到 nuclei")
    td = templates_dir()
    td.mkdir(parents=True, exist_ok=True)
    cmd = [nuc, "-update-templates", "-ud", str(td)]
    print("[*]", " ".join(cmd), flush=True)
    rc = subprocess.call(cmd)
    n_yml = sum(1 for _ in td.rglob("*.yaml")) if td.is_dir() else 0
    print(f"[done] rc={rc} templates_dir={td} yaml≈{n_yml}")
    return rc


def _nuclei_template_flags(args: argparse.Namespace) -> tuple[list[str], str]:
    """选模板：-t 优先；否则默认本库指纹；--tags/--community/--template-id 才挂社区库。

    返回 (flags, mode)。mode: explicit | custom | community+custom
    """
    extras = [x for x in (getattr(args, "templates", None) or []) if x]
    if extras:
        flags: list[str] = []
        for raw in extras:
            flags += ["-t", str(resolve_template_arg(raw))]
        return flags, "explicit"
    custom_ok = CUSTOM_TEMPLATES.is_dir() and any(CUSTOM_TEMPLATES.glob("*.yaml"))
    if getattr(args, "custom_only", False):
        if not custom_ok:
            raise SystemExit("[err] custom-templates 为空")
        return ["-t", str(CUSTOM_TEMPLATES)], "custom"
    want_community = bool(
        getattr(args, "community", False) or args.tags or args.template_id
    )
    flags = []
    td = templates_dir()
    if want_community and td.is_dir():
        flags += ["-t", str(td)]
    if custom_ok:
        flags += ["-t", str(CUSTOM_TEMPLATES)]
    if not flags:
        raise SystemExit("[err] 无可用模板。先 update-templates 或检查 custom-templates/")
    mode = "community+custom" if want_community else "custom"
    return flags, mode


def cmd_nuclei(args: argparse.Namespace) -> int:
    ensure_scope(args.url)
    nuc = find_nuclei()
    if not nuc:
        raise SystemExit("[err] 找不到 nuclei")
    td = templates_dir()
    out_dir = case_dir(args.case)
    jsonl = out_dir / "nuclei.jsonl"
    tflags, mode = _nuclei_template_flags(args)
    if mode == "custom" and not getattr(args, "custom_only", False) and not getattr(args, "templates", None):
        print("[hint] 默认只跑 custom-templates；社区库请加 --tags / --community / --template-id")
    cmd = [
        nuc,
        "-u",
        args.url,
        "-jsonl",
        "-o",
        str(jsonl),
        "-silent",
        "-duc",
        "-ud",
        str(td),
        *tflags,
    ]
    if args.tags:
        cmd += ["-tags", args.tags]
    if getattr(args, "exclude_tags", None):
        cmd += ["-etags", args.exclude_tags]
    if args.severity:
        cmd += ["-severity", args.severity]
    if args.template_id:
        cmd += ["-id", args.template_id]
    if args.rate_limit:
        cmd += ["-rate-limit", str(args.rate_limit)]
    if args.insecure:
        cmd += ["-tlsi"]
    meta = {
        "ts": _now(),
        "url": args.url,
        "mode": mode,
        "cmd": cmd,
        "templates_dir": str(td),
    }
    (out_dir / "nuclei_cmd.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print("[*]", " ".join(cmd), flush=True)
    if getattr(args, "dry_run", False):
        print("[dry-run] 未发请求")
        return 0
    rc = subprocess.call(cmd)
    findings = 0
    if jsonl.is_file():
        findings = sum(1 for _ in jsonl.open(encoding="utf-8") if _.strip())
    print(f"[done] rc={rc} findings={findings} out={jsonl}")
    return rc


def _template_meta(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8", errors="ignore")[:8000]
    tid = ""
    name = ""
    tags = ""
    severity = ""
    for line in text.splitlines():
        if not tid and line.startswith("id:"):
            tid = line.split(":", 1)[1].strip()
        elif not name and re.match(r"\s+name:", line):
            name = line.split(":", 1)[1].strip().strip("'\"")
        elif not severity and re.match(r"\s+severity:", line):
            severity = line.split(":", 1)[1].strip()
        elif not tags and re.match(r"\s+tags:", line):
            tags = line.split(":", 1)[1].strip()
        if tid and name and tags and severity:
            break
    return {
        "id": tid or path.stem,
        "name": name,
        "severity": severity,
        "tags": tags,
        "path": str(path.relative_to(ENGINE)) if path.is_relative_to(ENGINE) else str(path),
    }


def iter_template_files(root: Path) -> Iterator[Path]:
    if not root.is_dir():
        return
    yield from root.rglob("*.yaml")


def find_template_by_id(tid: str) -> Path | None:
    needle = tid.lower().strip()
    if not needle:
        return None
    custom_hits: list[Path] = []
    if CUSTOM_TEMPLATES.is_dir():
        for p in CUSTOM_TEMPLATES.glob("*.yaml"):
            meta = _template_meta(p)
            blob = f"{meta['id']} {p.stem}".lower()
            if needle == meta["id"].lower() or needle == p.stem.lower():
                return p
            if needle in blob:
                custom_hits.append(p)
    if custom_hits:
        return custom_hits[0]
    td = templates_dir()
    m = re.match(r"cve-(\d{4})-(\d+)", needle)
    if m and td.is_dir():
        guess = td / "http" / "cves" / m.group(1) / f"CVE-{m.group(1)}-{m.group(2)}.yaml"
        if guess.is_file():
            return guess
    if td.is_dir():
        for p in td.rglob("*.yaml"):
            if needle not in p.stem.lower() and needle not in p.name.lower():
                continue
            meta = _template_meta(p)
            if meta["id"].lower() == needle or p.stem.lower() == needle:
                return p
    return None


def cmd_version(_: argparse.Namespace) -> int:
    nuc = find_nuclei()
    if not nuc:
        print("[err] 找不到 nuclei。本机: bash scripts/install-arsenal-macos.sh")
        return 1
    print(f"[bin] {nuc}")
    rc, out = _run_nuclei(["-version", "-duc", "-nc"], timeout=20)
    print(_nuclei_version_line(out) or f"[version] rc={rc}")
    td = templates_dir()
    print(f"[templates] {td} yaml≈{_count_yaml(td)}")
    print(f"[custom] yaml={_count_yaml(CUSTOM_TEMPLATES)}")
    print("[upstream] https://github.com/projectdiscovery/nuclei/releases/latest")
    print("[docs] https://docs.projectdiscovery.io/tools/nuclei")
    print("[handbook] 传承/针匣·手册.md")
    return 0 if rc == 0 else rc


def cmd_learn(_: argparse.Namespace) -> int:
    handbook = (ENGINE / "传承" / "针匣·手册.md" if (ENGINE / "传承" / "针匣·手册.md").is_file() else ENGINE / "docs" / "playbooks" / "Nuclei引擎学习手册.md")
    print(
        """# Nuclei 在大爱仙尊里怎么用（速记）

引擎   tools/arsenal/bin/nuclei     ProjectDiscovery YAML 扫描器
社区   tools/1day-kit/nuclei-templates/   gitignore，约 1.3 万模板
本库   tools/1day-kit/custom-templates/   只指纹、不炸（~68）
入口   python3 tools/1day-kit/od_kit.py
证据   案卷/<案卷>/测绘/1day/

定位：L1 已知洞/误配。命中后切 nday_route / 专卡，禁止只扫 CVE 结案。
Actuator / 假支付 / GVA 等业务链永远优先于广谱 nuclei。

学 YAML：
  python3 tools/1day-kit/od_kit.py explain --id spring-actuator-unauth
  python3 tools/1day-kit/od_kit.py list-templates --q actuator
  python3 tools/1day-kit/od_kit.py validate

扫授权站：
  python3 炼蛊房/nday_route.py -u https://授权站 --case <案卷>
  python3 tools/1day-kit/od_kit.py nuclei --url https://授权站 --case <案卷> --custom-only
  python3 tools/1day-kit/od_kit.py nuclei --url https://授权站 --case <案卷> --tags cve,rce

官方：https://github.com/projectdiscovery/nuclei  ·  go install .../nuclei/v3/cmd/nuclei@latest
"""
    )
    print(f"[handbook] {handbook} exists={handbook.is_file()}")
    return 0


def cmd_explain(args: argparse.Namespace) -> int:
    p = find_template_by_id(args.id)
    if not p:
        print(f"[err] 找不到模板 id={args.id!r}。先 list-templates --q {args.id}")
        return 2
    meta = _template_meta(p)
    text = p.read_text(encoding="utf-8", errors="ignore")
    src = "本库 custom-templates" if CUSTOM_TEMPLATES in p.parents else "社区 nuclei-templates"
    print(f"# {meta['id']}")
    print(f"source: {src}")
    print(f"path:   {meta['path']}")
    print(f"name:   {meta['name']}")
    print(f"severity: {meta['severity']}")
    print(f"tags:   {meta['tags']}")
    print()
    print("怎么读：")
    print("  id/info     身份与严重度（本库只写探测，不写破坏 payload）")
    print("  http/dns/…  协议块；大爱仙尊默认 http")
    print("  matchers    命中条件（word/status/regex/dsl）")
    print("  extractors  抽证据（json/regex/kval）")
    print("  命中 = L1。业务口径仍走对应 Playbook/Skill。")
    print()
    print("--- yaml ---")
    print(text[:6000])
    if len(text) > 6000:
        print(f"\n… truncated {len(text) - 6000} bytes；完整文件见 path")
    return 0


def cmd_list_templates(args: argparse.Namespace) -> int:
    q = (args.q or "").lower().strip()
    roots: list[Path] = []
    if args.community:
        roots = [templates_dir()]
    elif args.custom or not q:
        roots = [CUSTOM_TEMPLATES]
    else:
        roots = [CUSTOM_TEMPLATES, templates_dir()]
    rows: list[dict[str, str]] = []
    limit = int(args.limit)
    for root in roots:
        if root is None or not root.is_dir():
            continue
        kind = "custom" if root == CUSTOM_TEMPLATES else "community"
        for p in iter_template_files(root):
            meta = _template_meta(p)
            blob = f"{meta['id']} {meta['name']} {meta['tags']} {p.name}".lower()
            if q and q not in blob:
                continue
            meta["kind"] = kind
            rows.append(meta)
            if len(rows) >= limit:
                break
        if len(rows) >= limit:
            break
    print(json.dumps({"q": q, "count": len(rows), "limit": limit, "hits": rows}, ensure_ascii=False, indent=2))
    return 0 if rows else 2


def cmd_validate(args: argparse.Namespace) -> int:
    nuc = find_nuclei()
    if not nuc:
        raise SystemExit("[err] 找不到 nuclei")
    target = CUSTOM_TEMPLATES if not args.community else templates_dir()
    if not target.is_dir():
        raise SystemExit(f"[err] 无目录 {target}")
    cmd = [nuc, "-validate", "-t", str(target), "-ud", str(templates_dir()), "-duc", "-nc"]
    print("[*]", " ".join(cmd), flush=True)
    return subprocess.call(cmd)


def cmd_tags(_: argparse.Namespace) -> int:
    seen: dict[str, int] = {}
    if CUSTOM_TEMPLATES.is_dir():
        for p in CUSTOM_TEMPLATES.glob("*.yaml"):
            tags = _template_meta(p)["tags"]
            for t in (x.strip() for x in tags.split(",") if x.strip()):
                seen[t] = seen.get(t, 0) + 1
    print("[custom tags]")
    for t, n in sorted(seen.items(), key=lambda kv: (-kv[1], kv[0])):
        print(f"  {t}\t{n}")
    print()
    print("社区全量标签：nuclei -tgl -ud tools/1day-kit/nuclei-templates")
    print("常用过滤：--tags cve,rce  /  --tags misconfig  /  --severity critical,high")
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    path = EXPLOITARIUM / args.id
    if not path.is_dir():
        raise SystemExit(f"[err] 无此条目: {args.id}")
    readme = path / "README.md"
    print(f"# {args.id}")
    print(f"path: {path}")
    if readme.is_file():
        print(readme.read_text(encoding="utf-8", errors="ignore")[:4000])
    else:
        for f in sorted(path.iterdir())[:30]:
            print(" -", f.name)
    return 0


def _cvebase_headers() -> dict[str, str]:
    hdrs = {
        "User-Agent": "大爱仙尊-1day-kit/cvebase",
        "Accept": "application/json",
    }
    key = (os.environ.get("CVEBASE_API_KEY") or "").strip()
    if key:
        hdrs["Authorization"] = f"Bearer {key}"
    return hdrs


def _ssl_ctx() -> ssl.SSLContext:
    try:
        import certifi  # type: ignore

        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


def cvebase_get(path: str, params: dict[str, Any] | None = None, timeout: int = 30) -> dict[str, Any]:
    q = urllib.parse.urlencode({k: v for k, v in (params or {}).items() if v is not None and v != ""})
    url = f"{CVEBASE_BASE}{path}"
    if q:
        url = f"{url}?{q}"
    req = urllib.request.Request(url, headers=_cvebase_headers(), method="GET")
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=timeout) as r:
            raw = r.read()
            remaining = r.headers.get("X-RateLimit-Remaining")
            data = json.loads(raw.decode("utf-8", "replace") or "{}")
            if isinstance(data, dict) and remaining is not None:
                data.setdefault("_http", {})["rate_limit_remaining"] = remaining
            return data if isinstance(data, dict) else {"raw": data}
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace") if e.fp else ""
        try:
            err = json.loads(body)
        except Exception:
            err = {"error": {"message": body[:500], "code": str(e.code)}}
        raise SystemExit(f"[cvebase] HTTP {e.code}: {json.dumps(err, ensure_ascii=False)[:400]}") from e
    except Exception as e:
        raise SystemExit(f"[cvebase] request failed: {e}") from e


def _local_cve_hints(cve_id: str) -> dict[str, Any]:
    """对照本库已有 Playbook / 自定义 nuclei。"""
    cid = cve_id.upper().strip()
    playbooks = list((ENGINE / "docs" / "playbooks").glob("*.md")) if (ENGINE / "docs" / "playbooks").is_dir() else []
    templates = list(CUSTOM_TEMPLATES.glob("*.yaml")) if CUSTOM_TEMPLATES.is_dir() else []
    pb_keys = {
        "CVE-2026-63077": ("TeamCity", "63077"),
        "CVE-2026-72898": ("Metabase未授权SQLi", "1day在野洞情报", "72898"),
        "CVE-2026-42945": ("NGINX-Rift", "nginx-rift", "42945"),
        "CVE-2026-16723": ("Fastjson", "16723"),
        "CVE-2026-18556": ("Ncentral认证绕过", "ncentral", "18556"),
        "CVE-2026-18577": ("Ncentral认证绕过", "ncentral", "18577"),
        "CVE-2026-8037": ("LoadMaster未授权RCE", "LoadMaster", "8037"),
        "CVE-2026-34486": ("Tomcat集群加密旁路", "Tomcat", "34486"),
        "CVE-2026-16812": ("VeloCloud编排器", "VeloCloud", "16812"),
        "CVE-2026-9198": ("Langflow未授权RCE", "Langflow", "9198"),
        "CVE-2026-50522": ("SharePoint未授权反序列化", "SharePoint", "50522"),
        "CVE-2026-58644": ("SharePoint未授权反序列化", "SharePoint", "58644"),
        "CVE-2026-64638": ("WordPress登录XSS", "XSS2Shell", "64638"),
        "CVE-2026-49972": ("Laravel双扩展上传", "laravel-mediable", "49972"),
        "CVE-2026-16232": ("SmartConsole认证绕过", "SmartConsole", "16232"),
        "CVE-2025-68686": ("FortiOS符号链接补丁旁路", "FortiOS", "68686"),
        "CVE-2026-63030": ("WordPress-REST注入", "63030", "author__not_in"),
        "CVE-2026-60137": ("WordPress-REST注入", "author__not_in", "60137"),
        "CVE-2026-0770": ("Langflow未授权RCE", "exec_globals", "0770"),
        "CVE-2021-29441": ("Nacos未授权", "nacos", "29441"),
        "CVE-2021-29442": ("Nacos未授权", "nacos", "29442"),
        "CVE-2021-43798": ("Grafana未授权", "grafana", "43798"),
        "CVE-2016-4437": ("Shiro-rememberMe", "shiro", "4437"),
        "CVE-2018-20062": ("ThinkPHP", "thinkphp", "20062"),
        "CVE-2019-9082": ("ThinkPHP", "thinkphp", "9082"),
        "CVE-2026-12800": ("WordPress-PremiumPackages", "wpdm", "12800", "发卡"),
        "CVE-2026-15906": ("WordPress-PremiumPackages", "wpdm", "15906"),
        "CVE-2026-39503": ("WordPress-EDD", "easy-digital-downloads", "39503", "发卡"),
        "CVE-2026-59524": ("WordPress-EDD", "easy-digital-downloads", "59524"),
        "CVE-2026-12476": ("WordPress-EDD", "easy-digital-downloads", "12476"),
        "CVE-2026-68820": ("Windows提权", "AFD", "68820"),
        "CVE-2026-64564": ("Linux主机提权", "容器逃逸", "SCTPhantom", "64564"),
    }
    keys = pb_keys.get(cid, (cid, cid.replace("CVE-", "")))
    pb_hits = [
        str(p.relative_to(ENGINE))
        for p in playbooks
        if any(k.lower() in p.name.lower() for k in keys)
    ]
    tpl_keys = {
        "CVE-2026-63077": "teamcity",
        "CVE-2026-72898": "metabase",
        "CVE-2026-42945": "nginx-rift",
        "CVE-2026-18556": "ncentral",
        "CVE-2026-18577": "ncentral",
        "CVE-2026-8037": "loadmaster-rce",
        "CVE-2026-34486": "tomcat-encrypt",
        "CVE-2026-16812": "velocloud",
        "CVE-2026-9198": "langflow",
        "CVE-2026-50522": "sharepoint-rce",
        "CVE-2026-58644": "sharepoint-rce",
        "CVE-2026-64638": "wordpress-xss2shell",
        "CVE-2026-49972": "laravel-mediable",
        "CVE-2026-16232": "smartconsole",
        "CVE-2025-68686": "fortios-symlink",
        "CVE-2026-63030": "wordpress-rest-sqli",
        "CVE-2026-60137": "wordpress-rest-sqli",
        "CVE-2026-0770": "langflow",
        "CVE-2021-29441": "nacos",
        "CVE-2021-29442": "nacos",
        "CVE-2021-43798": "grafana",
        "CVE-2016-4437": "shiro-rememberme",
        "CVE-2018-20062": "thinkphp-surface",
        "CVE-2019-9082": "thinkphp-surface",
        "CVE-2026-12800": "wpdm-premium-packages",
        "CVE-2026-15906": "wpdm-premium-packages",
        "CVE-2026-39503": "easy-digital-downloads",
        "CVE-2026-59524": "easy-digital-downloads",
        "CVE-2026-12476": "easy-digital-downloads",
    }
    token = tpl_keys.get(cid) or cid.lower().replace("cve-", "")
    tpl_hits = [str(t.relative_to(ENGINE)) for t in templates if token in t.name.lower()]
    return {"playbooks": sorted(set(pb_hits)), "custom_templates": sorted(set(tpl_hits))}


def _summarize_cve(data: dict[str, Any]) -> dict[str, Any]:
    ov = data.get("overview") or {}
    en = data.get("enrichment") or {}
    epss = en.get("epss") or {}
    kev = en.get("kev") or {}
    pri = en.get("priority") or {}
    return {
        "cve_id": data.get("cve_id"),
        "severity": data.get("severity") or ov.get("severity"),
        "cvss": data.get("cvss") or ov.get("cvss_score"),
        "description": (ov.get("description") or "")[:500],
        "cwes": ov.get("cwes"),
        "epss": epss.get("score") if isinstance(epss, dict) else epss,
        "epss_percentile": epss.get("percentile") if isinstance(epss, dict) else None,
        "in_kev": bool(kev.get("in_kev")) if isinstance(kev, dict) else False,
        "kev_date_added": kev.get("date_added") if isinstance(kev, dict) else None,
        "exploit_available": en.get("exploit_available"),
        "exploited_in_wild": en.get("exploited_in_wild"),
        "priority": pri.get("level") if isinstance(pri, dict) else pri,
        "total_documents": data.get("total_documents"),
        "local": _local_cve_hints(str(data.get("cve_id") or "")),
    }


def cmd_cvebase(args: argparse.Namespace) -> int:
    action = args.cvebase_cmd
    out_payload: dict[str, Any] = {"ts": _now(), "action": action, "source": "cvebase.io"}

    if action == "trending":
        data = cvebase_get("/api/trending")
        recent = data.get("recent_kev") or []
        top_epss = data.get("top_epss") or []
        rows = []
        print(f"[cvebase] recent_kev={len(recent)} top_epss={len(top_epss)} docs={data.get('total_documents')}")
        print("--- recent KEV ---")
        for item in recent[: int(args.limit)]:
            cid = item.get("cve_id")
            local = _local_cve_hints(str(cid or ""))
            row = {
                "cve_id": cid,
                "vendor": item.get("vendor"),
                "product": item.get("product"),
                "name": item.get("name"),
                "severity": item.get("severity"),
                "cvss": item.get("cvss_score"),
                "date_added": item.get("date_added"),
                "local": local,
            }
            rows.append(row)
            loc = ",".join(local.get("playbooks") or local.get("custom_templates") or ["-"])
            print(
                f"  {cid}  {item.get('severity')} {item.get('cvss_score')}  "
                f"{(item.get('product') or '')[:40]}  local={loc}"
            )
        out_payload["recent_kev"] = rows
        out_payload["raw_meta"] = {
            "total_kev": data.get("total_kev"),
            "exploited_in_wild_count": data.get("exploited_in_wild_count"),
            "exploit_available_count": data.get("exploit_available_count"),
        }

    elif action == "lookup":
        cve = args.cve.strip().upper()
        if not cve.startswith("CVE-"):
            raise SystemExit("[cvebase] --cve 需要形如 CVE-2026-72898")
        data = cvebase_get(f"/api/cve/{cve}")
        summary = _summarize_cve(data)
        out_payload["summary"] = summary
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        if args.docs:
            docs = cvebase_get(
                f"/api/cve/{cve}/documents",
                {"source_type": args.source_type or "exploit", "limit": str(args.limit)},
            )
            out_payload["documents"] = docs
            print(f"--- documents source_type={args.source_type or 'exploit'} total={docs.get('total')} ---")
            for r in (docs.get("results") or [])[: int(args.limit)]:
                print(f"  [{r.get('source')}] {(r.get('title') or '')[:90]}")
                if r.get("url"):
                    print(f"    {r.get('url')}")

    elif action == "search":
        params: dict[str, Any] = {
            "q": args.q,
            "limit": str(args.limit),
            "offset": str(args.offset or 0),
        }
        if args.kev:
            params["filter_kev"] = "true"
        if args.exploit:
            params["filter_exploit"] = "true"
        if args.wild:
            params["filter_wild"] = "true"
        if args.severity:
            params["severity"] = args.severity
        data = cvebase_get("/api/search", params)
        results = data.get("results") or []
        slim = []
        print(f"[cvebase] q={args.q!r} total={data.get('total')} page={data.get('page')}/{data.get('pages')}")
        for r in results[: int(args.limit)]:
            cves = r.get("cve_ids") or []
            cid = cves[0] if cves else None
            row = {
                "title": (r.get("title") or "")[:160],
                "cve_ids": cves,
                "severity": r.get("severity"),
                "epss": r.get("epss"),
                "in_kev": r.get("in_kev"),
                "priority": (r.get("priority") or {}).get("level") if isinstance(r.get("priority"), dict) else r.get("priority"),
                "url": r.get("url"),
                "local": _local_cve_hints(str(cid)) if cid else {},
            }
            slim.append(row)
            print(f"  {cid or '-'}  {row['severity']} epss={row['epss']} kev={row['in_kev']}  {row['title'][:80]}")
        out_payload["results"] = slim
        out_payload["risk_counts"] = data.get("risk_counts")

    else:
        raise SystemExit(f"[cvebase] unknown action {action}")

    if args.case:
        out = case_dir(args.case) / f"cvebase_{action}.json"
        out.write_text(json.dumps(out_payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"[ok] -> {out}")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="1day / nuclei / exploitarium / cvebase")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("doctor")
    d.set_defaults(func=cmd_doctor)

    learn = sub.add_parser("learn", help="Nuclei 在本库的速记（对照学习手册）")
    learn.set_defaults(func=cmd_learn)

    ver = sub.add_parser("version", help="nuclei 二进制 + 模板版本")
    ver.set_defaults(func=cmd_version)

    ex = sub.add_parser("explain", help="拆开一条 YAML 模板（先 custom 再社区）")
    ex.add_argument("--id", required=True, help="模板 id 或文件名，如 spring-actuator-unauth")
    ex.set_defaults(func=cmd_explain)

    lt = sub.add_parser("list-templates", help="列本库/社区模板")
    lt.add_argument("--q", help="按 id/name/tags 过滤；有关键词时会搜社区库")
    lt.add_argument("--custom", action="store_true", help="只列 custom-templates")
    lt.add_argument("--community", action="store_true", help="只列官方 nuclei-templates")
    lt.add_argument("--limit", type=int, default=40)
    lt.set_defaults(func=cmd_list_templates)

    va = sub.add_parser("validate", help="nuclei -validate 校验模板")
    va.add_argument("--community", action="store_true", help="校验官方库（慢）")
    va.set_defaults(func=cmd_validate)

    tg = sub.add_parser("tags", help="本库 custom-templates 标签统计")
    tg.set_defaults(func=cmd_tags)

    i = sub.add_parser("index", help="重建 exploitarium 索引")
    i.add_argument("--case")
    i.set_defaults(func=cmd_index)

    s = sub.add_parser("search", help="搜 exploitarium")
    s.add_argument("--q", required=True)
    s.set_defaults(func=cmd_search)

    sh = sub.add_parser("show", help="展示某条 PoC README")
    sh.add_argument("--id", required=True)
    sh.set_defaults(func=cmd_show)

    u = sub.add_parser("update-templates", help="nuclei -update-templates")
    u.set_defaults(func=cmd_update_templates)

    n = sub.add_parser("nuclei", help="授权目标 nuclei 扫描")
    n.add_argument("--url", required=True)
    n.add_argument("--case", required=True)
    n.add_argument("--tags", help="逗号分隔 nuclei 标签，如 cve,rce")
    n.add_argument("--exclude-tags", dest="exclude_tags", help="排除标签，如 dos,fuzz")
    n.add_argument("--severity", help="严重程度过滤，如 critical,high,medium")
    n.add_argument("--template-id", dest="template_id", help="nuclei 模板 ID（精确匹配）")
    n.add_argument(
        "-t",
        "--template",
        dest="templates",
        action="append",
        default=[],
        help="模板文件或目录（可重复；相对仓库根）。nday_route / 手法卡都走这个",
    )
    n.add_argument("--custom-only", action="store_true", help="只跑本库 custom-templates")
    n.add_argument("--community", action="store_true", help="挂官方 nuclei-templates（默认不挂）")
    n.add_argument("--dry-run", action="store_true", help="只打印命令，不发请求")
    n.add_argument("--rate-limit", type=int, default=50)
    n.add_argument("--insecure", action="store_true")
    n.set_defaults(func=cmd_nuclei)

    cb = sub.add_parser("cvebase", help="查 cvebase.io（KEV/EPSS/利用情报）")
    cb_sub = cb.add_subparsers(dest="cvebase_cmd", required=True)

    t = cb_sub.add_parser("trending", help="近期 KEV / 趋势")
    t.add_argument("--limit", type=int, default=12)
    t.add_argument("--case")
    t.set_defaults(func=cmd_cvebase)

    lk = cb_sub.add_parser("lookup", help="单 CVE 富化")
    lk.add_argument("--cve", required=True)
    lk.add_argument("--docs", action="store_true", help="再拉 /documents（默认 exploit）")
    lk.add_argument("--source-type", default="exploit", help="documents 的 source_type")
    lk.add_argument("--limit", type=int, default=10)
    lk.add_argument("--case")
    lk.set_defaults(func=cmd_cvebase)

    cs = cb_sub.add_parser("search", help="语义搜索")
    cs.add_argument("--q", required=True)
    cs.add_argument("--limit", type=int, default=8)
    cs.add_argument("--offset", type=int, default=0)
    cs.add_argument("--kev", action="store_true")
    cs.add_argument("--exploit", action="store_true")
    cs.add_argument("--wild", action="store_true")
    cs.add_argument("--severity", help="critical,high,medium,low")
    cs.add_argument("--case")
    cs.set_defaults(func=cmd_cvebase)

    args = p.parse_args()
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
