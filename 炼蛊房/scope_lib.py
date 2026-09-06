#!/usr/bin/env python3
"""授权 scope 读写与「主站链发现 → 静默扩权」共用库。

总表只保留 `*.根域` + 未被通配覆盖的精确 host/IP。
禁止把 https://、www、同一根域的五份拷贝写进 company.json。
"""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime, UTC
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


def repo_root(start: Path | None = None) -> Path:
    """脚本在 炼蛊房/ 或开源 炼蛊房/ 时都能落到本仓根，不爬到旁边目录。"""
    here = Path(start or __file__).resolve()
    if here.is_file():
        here = here.parent
    for p in (here, *here.parents):
        if (p / "杀招").is_dir() and (p / "炼蛊房").is_dir():
            return p
        if (p / "杀招").is_dir() and (p / "炼蛊房").is_dir():
            return p
    if here.name == "炼蛊房":
        return here.parent
    if here.name == "ops" and here.parent.name == "tools":
        return here.parents[1]
    return here.parents[1] if here.name == "ops" else here.parent


ENGINE = repo_root(Path(__file__))
COMPANY = ENGINE / "config" / "scope.company.json"
SITES = ENGINE / "config" / "scope_sites"
OSS_SCOPE = ENGINE / "态度蛊.json"


def is_oss_layout() -> bool:
    """开源版洞府：杀招 + 炼蛊房。大爱仙尊工作区不是这个布局。"""
    return (ENGINE / "杀招").is_dir() and (ENGINE / "炼蛊房").is_dir()


def evidence_root() -> Path:
    """案卷根。开源版写 `案卷/`，工作区写 `案卷/`。"""
    if is_oss_layout() or (ENGINE / "案卷").is_dir():
        return ENGINE / "案卷"
    return ENGINE / "案卷"


def safe_case_name(case: str) -> str:
    """案卷名闸：禁止 ../ 逃出 evidence_root。空串放行（表示不落案卷）。"""
    c = (case or "").strip()
    if not c:
        return ""
    if any(x in c for x in ("/", "\\", "..")) or c in {".", ".."}:
        raise SystemExit("[!] --case 必须是案卷名，不能含路径")
    return c


def scope_file() -> Path:
    """授权总表。工作区用 company.json；开源版用根目录 态度蛊.json。"""
    if COMPANY.is_file():
        return COMPANY
    if OSS_SCOPE.is_file() or is_oss_layout():
        return OSS_SCOPE
    return COMPANY

# 静默扩权时仍拒绝的全球基础设施（避免把 CDN/静态域写进 targets）
DENY_SUFFIXES = (
    "cloudflare.com",
    "cloudflare.net",
    "cloudflareinsights.com",
    "googleapis.com",
    "gstatic.com",
    "google.com",
    "googleusercontent.com",
    "facebook.com",
    "fbcdn.net",
    "apple.com",
    "microsoft.com",
    "akamai.net",
    "akamaiedge.net",
    "fastly.net",
    "edgekey.net",
    "jquery.com",
    "jsdelivr.net",
    "unpkg.com",
    "github.com",
    "githubusercontent.com",
    "w3.org",
    "schema.org",
    "doubleclick.net",
    "googletagmanager.com",
    "challenges.cloudflare.com",
)

_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_NUMERIC_LABELS_RE = re.compile(r"^(?:\d{1,3}\.)+\d{1,3}$")
_INDEX: dict[str, Any] | None = None
_NOTES_CAP = 800

def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, data: dict[str, Any]) -> None:
    """原子写入。company 先压缩 targets，避免 2 万行 pretty JSON 卡死编辑器。"""
    payload = data
    if path.resolve() == COMPANY.resolve():
        payload = dict(data)
        payload["targets"] = compact_targets(list(payload.get("targets") or []))
        notes = payload.get("notes") or ""
        if isinstance(notes, str) and len(notes) > _NOTES_CAP:
            payload["notes"] = (
                notes[:400].rstrip()
                + "\n…(扩权流水只写案卷 案卷/scope_expand.json，总表不再追加)"
            )
    text = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)
    invalidate_scope_cache()


def host_of(url_or_host: str) -> str:
    s = (url_or_host or "").strip()
    if not s:
        return ""
    if "://" in s or s.startswith("//"):
        return (urlparse(s if "://" in s else "https:" + s).hostname or "").lower()
    head = s.split("/")[0].strip()
    if head.startswith("["):
        end = head.find("]")
        if end > 1:
            return head[1:end].lower()
        return head.strip("[]").lower()
    if head.count(":") == 1:
        left, right = head.split(":", 1)
        if left and right.isdigit():
            return left.lower().lstrip(".")
    if head.count(":") >= 2:
        return head.lower().strip(".")
    return head.split(":")[0].lower().lstrip(".")


def _host_matches(host: str, pattern: str) -> bool:
    host = host.lower().strip(".")
    pattern = pattern.lower().strip(".")
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return host == suffix or host.endswith("." + suffix)
    return host == pattern


def target_host(pattern: str) -> str:
    p = (pattern or "").strip()
    if not p:
        return ""
    if "://" in p or p.startswith("//"):
        return (urlparse(p if "://" in p else "https:" + p).hostname or "").lower()
    if re.match(r"^[\w*.-]+(?::\d+)?$", p):
        return p.split(":")[0].lower()
    return p.lower()


def _looks_ipv4(h: str) -> bool:
    return bool(_IPV4_RE.match(h.lstrip("*.")))


def _numeric_host(h: str) -> bool:
    return bool(_NUMERIC_LABELS_RE.match(h.lstrip("*.")))


def compact_targets(targets: list[Any]) -> list[str]:
    """只留 `*.根域` + 通配盖不住的精确 host/IP。覆盖面不缩小。"""
    wild: set[str] = set()
    exact: set[str] = set()
    ipish: set[str] = set()
    for t in targets:
        if not isinstance(t, str):
            continue
        raw = t.strip()
        if not raw:
            continue
        if raw.startswith("*."):
            suf = raw[2:].lower().strip(".")
            if not suf:
                continue
            if _numeric_host(suf):
                ipish.add("*." + suf)
            else:
                wild.add(suf)
            continue
        h = host_of(raw) or raw.lower().strip(".")
        if not h or h.startswith("*"):
            continue
        if _numeric_host(h):
            ipish.add(h)
            continue
        exact.add(h)
    kept_exact = [
        h for h in exact
        if not any(h == w or h.endswith("." + w) for w in wild)
    ]
    out = [f"*.{w}" for w in sorted(wild)]
    out.extend(sorted(ipish))
    out.extend(sorted(kept_exact))
    return list(dict.fromkeys(out))


def invalidate_scope_cache() -> None:
    global _INDEX
    _INDEX = None


def _iter_patterns(scope: dict[str, Any]) -> list[str]:
    raw: list[Any] = list(scope.get("targets") or [])
    raw.extend(scope.get("domains") or [])
    for s in scope.get("sites") or []:
        if isinstance(s, dict):
            raw.append(s.get("wildcard") or "")
            raw.append(s.get("domain") or "")
        else:
            raw.append(s)
    return [x for x in raw if isinstance(x, str) and x.strip()]


def _index_from(scope: dict[str, Any]) -> dict[str, Any]:
    exact: set[str] = set()
    wild: set[str] = set()
    for t in _iter_patterns(scope):
        if t.startswith("*."):
            suf = t[2:].lower().strip(".")
            if suf:
                wild.add(suf)
            continue
        h = target_host(t)
        if h.startswith("*."):
            wild.add(h[2:].strip("."))
        elif h:
            exact.add(h)
    return {"exact": exact, "wild": tuple(wild)}


def _load_scope_blob() -> dict[str, Any]:
    """合并工作区 company.json 与开源版 态度蛊.json。"""
    data: dict[str, Any] = {"targets": []}
    for path in (COMPANY, OSS_SCOPE):
        if not path.is_file():
            continue
        try:
            chunk = load_json(path)
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            continue
        for key in ("targets", "domains"):
            for t in chunk.get(key) or []:
                if t not in data["targets"]:
                    data["targets"].append(t)
        if chunk.get("note") and not data.get("note"):
            data["note"] = chunk.get("note")
    return data


def _scope_mtime() -> float:
    latest = -1.0
    for path in (COMPANY, OSS_SCOPE):
        try:
            latest = max(latest, path.stat().st_mtime)
        except OSError:
            continue
    return latest


def _company_index() -> dict[str, Any]:
    global _INDEX
    mtime = _scope_mtime()
    if _INDEX and _INDEX.get("mtime") == mtime:
        return _INDEX
    data = _load_scope_blob()
    idx = _index_from(data)
    idx["mtime"] = mtime
    idx["data"] = data
    _INDEX = idx
    return idx


def in_scope(host_or_url: str, scope: dict[str, Any] | None = None) -> bool:
    host = host_of(host_or_url)
    if not host:
        return False
    idx = _index_from(scope) if scope is not None else _company_index()
    if host in idx["exact"]:
        return True
    for suf in idx["wild"]:
        if host == suf or host.endswith("." + suf):
            return True
    return False


def require_in_scope(
    host_or_url: str,
    *,
    scope: dict[str, Any] | None = None,
    allow_loopback: bool = False,
    quiet: bool = False,
) -> str:
    """fail-closed 授权闸门：目标不在 scope 时直接退出（exit 2）。

    统一替代各 probe 脚本自写的 `_scope_ok`（那些在配置缺失/解析失败时 return True，
    属于 fail-open 越权风险）。返回归一化后的 host 供调用方复用。
    """
    host = host_of(host_or_url)
    if not host:
        sys.stderr.write("[scope] 拒绝：空目标\n")
        raise SystemExit(2)
    if allow_loopback and host in ("127.0.0.1", "localhost", "::1"):
        return host
    if is_denied(host):
        sys.stderr.write(f"[scope] 拒绝：{host} 属基础设施/第三方域，禁止直接打\n")
        raise SystemExit(2)
    if in_scope(host, scope):
        return host
    if not quiet:
        if is_oss_layout():
            sys.stderr.write(
                f"[scope] 拒绝：{host} 不在 态度蛊.json。\n"
                f"        先立约： python3 炼蛊房/scope_expand.py --grant {host} --case <案> --note '授权'\n"
                f"        或把域名写进仓库根目录 态度蛊.json 的 targets。\n"
            )
        else:
            sys.stderr.write(
                f"[scope] 拒绝：{host} 不在 授权范围。\n"
                f"        先授权： python3 炼蛊房/scope_expand.py --grant {host} --case <案卷> --note '用户授权'\n"
            )
    raise SystemExit(2)


def is_denied(host: str) -> bool:
    h = host.lower().strip(".")
    for suf in DENY_SUFFIXES:
        if h == suf or h.endswith("." + suf):
            return True
    return False


def registrable_guess(host: str) -> str:
    """粗粒度 eTLD+1 猜测（够用；不做完整 PSL）。"""
    parts = host.lower().strip(".").split(".")
    if len(parts) <= 2:
        return host.lower().strip(".")
    if parts[-2] in {"co", "com", "net", "org", "ac", "gov"} and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def entries_for_host(host: str) -> list[str]:
    """新授权只写一条：IP 写精确值，域名写 `*.根域`。"""
    host = host.lower().strip(".")
    if not host:
        return []
    if _looks_ipv4(host):
        return [host]
    root = registrable_guess(host)
    return [f"*.{root}"]


def merge_targets(existing: list[str], add: list[str]) -> tuple[list[str], list[str]]:
    """返回 (new_list, actually_added)。已有等价 host 则跳过。"""
    have = set(existing)
    covered_hosts = {target_host(t) for t in existing if target_host(t)}
    added: list[str] = []
    new = list(existing)
    for t in add:
        if t in have:
            continue
        new.append(t)
        have.add(t)
        added.append(t)
        h = target_host(t)
        if h:
            covered_hosts.add(h)
    return compact_targets(new), added


def silent_expand(
    *,
    parent: str,
    discovered: list[str],
    site_scope: Path | None = None,
    case: str = "",
    note: str = "",
) -> dict[str, Any]:
    """
    从已授权主站发现的域名/URL → 静默写入 site scope + company。
    要求 parent 已在 company；discovered 中 deny 列表跳过。
    """
    dest = scope_file()
    company = load_json(dest) if dest.is_file() else {"targets": []}
    parent_host = host_of(parent)
    if not in_scope(parent_host, company):
        raise ValueError(f"主站 {parent_host} 不在授权表，拒绝扩权")

    report: dict[str, Any] = {
        "generated_at": datetime.now(UTC).isoformat(),
        "parent": parent_host,
        "policy": "silent_expand_from_authorized_parent",
        "requested": discovered,
        "skipped_denied": [],
        "skipped_already": [],
        "added_company": [],
        "added_site": [],
        "note": note,
        "case": case,
    }

    to_add: list[str] = []
    for raw in discovered:
        h = host_of(raw)
        if not h:
            continue
        if is_denied(h):
            report["skipped_denied"].append(h)
            continue
        if in_scope(h, company):
            report["skipped_already"].append(h)
            continue
        to_add.extend(entries_for_host(h))

    if not to_add:
        report["ok"] = True
        report["changed"] = False
        return report

    new_targets, added = merge_targets(list(company.get("targets") or []), to_add)
    line = ""
    if added:
        company["targets"] = new_targets
        stamp = datetime.now(UTC).strftime("%Y-%m-%d")
        hosts = ", ".join(sorted({host_of(x) or x for x in added}))
        line = f"静默扩权({stamp}): 主站 {parent_host} → {hosts}"
        if note:
            line += f" ({note[:80]})"
        if dest.resolve() == COMPANY.resolve():
            save_json(COMPANY, company)
        else:
            dest.write_text(json.dumps(company, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            invalidate_scope_cache()
        report["added_company"] = added

    if site_scope and site_scope.is_file():
        site = load_json(site_scope)
        st, sadd = merge_targets(list(site.get("targets") or site.get("domains") or []), to_add)
        if sadd:
            if "targets" in site:
                site["targets"] = st
            else:
                site["domains"] = [x.lstrip("*.") if isinstance(x, str) else x for x in st]
            if line:
                site["note"] = ((site.get("note") or "") + " | " + line)[:500]
            save_json(site_scope, site)
            report["added_site"] = sadd

    report["ok"] = True
    report["changed"] = bool(report["added_company"] or report["added_site"])

    if case:
        out = evidence_root() / case / "测绘"
        out.mkdir(parents=True, exist_ok=True)
        path = out / "scope_expand.json"
        prev = []
        if path.is_file():
            try:
                prev = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(prev, list):
                    prev = [prev]
            except Exception:
                prev = []
        prev.append(report)
        path.write_text(json.dumps(prev, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        report["log"] = str(path)

    return report


def compact_company() -> dict[str, Any]:
    """压缩总表。覆盖面不变，条数下降。"""
    dest = scope_file()
    if not dest.is_file():
        return {"ok": False, "reason": "no-scope-file", "path": str(dest)}
    company = load_json(dest)
    before = len(company.get("targets") or [])
    after_list = compact_targets(list(company.get("targets") or []))
    company["targets"] = after_list
    notes = company.get("notes") or ""
    if isinstance(notes, str) and len(notes) > _NOTES_CAP:
        company["notes"] = (
            "授权总表已压缩；历史静默扩权流水见各案卷 案卷/scope_expand.json。"
        )
    if dest.resolve() == COMPANY.resolve():
        save_json(COMPANY, company)
    else:
        dest.write_text(json.dumps(company, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        invalidate_scope_cache()
    return {
        "ok": True,
        "before": before,
        "after": len(after_list),
        "path": str(dest),
    }


def grant(
    *,
    host: str,
    case: str = "",
    note: str = "",
    site_id: str = "",
) -> dict[str, Any]:
    """新目标写入单站 JSON + 并入 company。不要整文件手改 2 万行总表。"""
    h = host_of(host) or host.lower().strip().strip("/")
    if not h:
        raise ValueError("空 host")
    if is_denied(h):
        raise ValueError(f"基础设施域拒绝写入: {h}")
    to_add = entries_for_host(h)
    dest = scope_file()
    if is_oss_layout() and not COMPANY.is_file():
        dest = OSS_SCOPE
        existing = load_json(dest) if dest.is_file() else {"targets": [], "note": "没立约不准祭"}
        already = in_scope(h, existing)
        new_targets, added = merge_targets(list(existing.get("targets") or []), to_add)
        if added:
            existing["targets"] = new_targets
            if note:
                existing["note"] = ((existing.get("note") or "") + " | " + note)[:500]
            dest.write_text(json.dumps(existing, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            invalidate_scope_cache()
        return {
            "ok": True,
            "host": h,
            "already_in_company": already,
            "added_company": added,
            "site": str(dest),
            "targets": to_add,
        }
    company = load_json(COMPANY) if COMPANY.is_file() else {"targets": []}
    already = in_scope(h, company)
    new_targets, added = merge_targets(list(company.get("targets") or []), to_add)
    if added:
        company["targets"] = new_targets
        save_json(COMPANY, company)

    sid = site_id or re.sub(r"[^a-z0-9._-]+", "_", h.replace(".", "_"))
    SITES.mkdir(parents=True, exist_ok=True)
    site_path = SITES / f"scope.{sid}.json"
    site: dict[str, Any]
    if site_path.is_file():
        site = load_json(site_path)
        domains = list(site.get("domains") or [])
        root = registrable_guess(h)
        for x in (h, root):
            if x and x not in domains:
                domains.append(x)
        site["domains"] = domains
        if note:
            site["note"] = ((site.get("note") or "") + " | " + note)[:500]
        if case:
            site["case"] = case
        save_json(site_path, site)
    else:
        root = registrable_guess(h)
        site = {
            "authorization_level": "highest",
            "operation_policy": "unrestricted",
            "technique_whitelist": False,
            "allow_pentest": True,
            "site_id": sid,
            "name": h,
            "domains": [root, h] if root != h else [h],
            "case": case,
            "note": note,
            "added": datetime.now(UTC).strftime("%Y-%m-%d"),
        }
        save_json(site_path, site)

    return {
        "ok": True,
        "host": h,
        "already_in_company": already,
        "added_company": added,
        "site": str(site_path),
        "targets": to_add,
    }


def write_probe_json(
    payload: dict[str, Any],
    *,
    case: str = "",
    out: Path | None = None,
    case_subdir: str = "",
    filename: str = "surface.json",
) -> Path:
    """同时写入 --case 案卷目录和 --out。kit_run 读 --out，案卷归档走 --case。"""
    text = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    written: list[Path] = []
    if case:
        case = safe_case_name(case)
        d = evidence_root() / case / "测绘"
        if case_subdir:
            d = d / case_subdir
        d.mkdir(parents=True, exist_ok=True)
        p = d / filename
        p.write_text(text, encoding="utf-8")
        written.append(p)
    if out:
        op = Path(out)
        op.parent.mkdir(parents=True, exist_ok=True)
        op.write_text(text, encoding="utf-8")
        written.append(op)
    if not written:
        # 无 --case/--out 不往 cwd 落 surface.json，避免污染仓库根
        return Path(filename)
    return written[-1] if out else written[0]
