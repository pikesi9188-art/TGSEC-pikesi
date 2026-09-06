#!/usr/bin/env python3
"""授权精简候选：盘点；prune --apply 才归档/删授权。

对照 scope_sites ↔ 案卷顶层目录。不递归扫 exports/ 证据树，
不读 scope.company.json 正文。

  python3 炼蛊房/scope_stale_candidates.py snapshot
  python3 炼蛊房/scope_stale_candidates.py compact          # 同根合并预览
  python3 炼蛊房/scope_stale_candidates.py compact --apply
  python3 炼蛊房/scope_stale_candidates.py prune
  python3 炼蛊房/scope_stale_candidates.py prune --apply
"""
from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from datetime import date, datetime
from pathlib import Path
from typing import Any

import shutil

from scope_lib import (
    SITES,
    ENGINE,
    COMPANY,
    registrable_guess,
    _looks_ipv4,
    load_json,
    save_json,
    compact_company,
    target_host,
    host_of,
)

CASES = ENGINE / "案卷"
BY_SITE = ENGINE / "scripts" / "by_site"
SKIP_CASE = frozenset(
    {
        "reports",
        "cards",
        "_board",
        "_archive",
        "_templates",
        "_autocve_lab_20260805",
        "_kb",
        "exports",
        "恢复报告",
    }
)
INFRA_ROOTS = frozenset(
    {
        "aliyuncs.com",
        "myqcloud.com",
        "amazonaws.com",
        "cloudflare.com",
        "cloudflare.net",
        "googleapis.com",
        "azurewebsites.net",
        "tencentcdb.com",
        "qingstor.com",
    }
)
CLOSE_RE = re.compile(
    r"已出卡|超管已|后台已[入登]|改密成功|已登录超管|已拿管理|出卡验证",
    re.I,
)
CLOSE_FILE_RE = re.compile(
    r"(?i)creds_vault|secrets_inventory|admin_dump|heap_cred|"
    r"hidden_admin|wp_users|backdoor|改密|超管",
)
BATCH_TOUCHES = {date(2026, 8, 9), date(2026, 8, 18)}  # 大批量改时间，不当最后作业
COLD_DAYS = 14
COOL_DAYS = 7
TODAY = date.today()
SENSITIVE_KEYS = frozenset(
    {"credentials", "credential", "authorized_password", "authorized_account"}
)


def _safe_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _mtime_date(path: Path) -> date | None:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime).date()
    except OSError:
        return None


def _case_stem(name: str) -> str:
    m = re.match(r"^(.+?)_(\d{8})$", name)
    return m.group(1).lower() if m else name.lower()


def _root_of(host: str) -> str:
    h = (host or "").strip().lower().strip(".")
    if not h:
        return ""
    if _looks_ipv4(h):
        return "IP"
    root = registrable_guess(h)
    if root in INFRA_ROOTS or any(h.endswith("." + x) for x in INFRA_ROOTS):
        return "INFRA"
    return root


def _load_sites() -> list[dict[str, Any]]:
    rows = []
    if not SITES.is_dir():
        return rows
    for p in SITES.iterdir():
        if p.suffix != ".json" or not p.name.startswith("scope."):
            continue
        data = _safe_json(p)
        name = str(data.get("name") or data.get("site_id") or p.stem[6:]).strip()
        domains = [str(x) for x in (data.get("domains") or []) if x]
        host = name or (domains[0] if domains else p.stem[6:].replace("_", "."))
        rows.append(
            {
                "file": p.name,
                "site_id": str(data.get("site_id") or ""),
                "name": host,
                "root": _root_of(host) or _root_of(domains[0] if domains else ""),
                "case": str(data.get("case") or ""),
                "added": str(data.get("added") or ""),
                "note": str(data.get("note") or "")[:80],
                "n_domains": len(domains) or 1,
            }
        )
    return rows


def _status_path(d: Path, case: str) -> Path | None:
    named = d / f"STATUS_{case}.md"
    if named.is_file():
        return named
    plain = d / "STATUS.md"
    if plain.is_file() or plain.is_symlink():
        return plain
    return None


def _load_cases() -> list[dict[str, Any]]:
    rows = []
    if not CASES.is_dir():
        return rows
    for d in CASES.iterdir():
        if not d.is_dir() or d.name.startswith("_") or d.name in SKIP_CASE:
            continue
        triage = _safe_json(d / "triage.json")
        retro = _safe_json(d / "retrospective.json")
        status = _status_path(d, d.name)
        takeover = (d / "接管").is_dir()
        close_files: list[str] = []
        if takeover:
            try:
                for x in (d / "接管").iterdir():
                    if x.name in {".DS_Store", "__pycache__"}:
                        continue
                    if CLOSE_FILE_RE.search(x.name):
                        close_files.append(x.name)
            except OSError:
                pass
        close = bool(close_files)
        snippet = ""
        if status and status.is_file():
            try:
                snippet = status.read_text(encoding="utf-8", errors="replace")[:4000]
            except OSError:
                snippet = ""
            if snippet and CLOSE_RE.search(snippet):
                close = True
        outcome = str(retro.get("outcome") or "").upper()
        if outcome in {"SUCCESS"}:
            close = True
        opened = None
        m = re.search(r"_(\d{8})$", d.name)
        if m:
            try:
                opened = date(int(m.group(1)[:4]), int(m.group(1)[4:6]), int(m.group(1)[6:8]))
            except ValueError:
                opened = None
        root_files = []
        try:
            root_files = [
                x.name
                for x in d.iterdir()
                if x.name not in {".DS_Store", "__pycache__"}
            ]
        except OSError:
            pass
        dates: list[date] = []
        tu = str(triage.get("updated_at") or "")[:10]
        if tu:
            try:
                dates.append(date.fromisoformat(tu))
            except ValueError:
                pass
        for p in (status, d / "triage.json"):
            if p and Path(p).is_file():
                dm = _mtime_date(Path(p))
                if dm and dm not in BATCH_TOUCHES:
                    dates.append(dm)
        dm = _mtime_date(d)
        if dm and dm not in BATCH_TOUCHES:
            dates.append(dm)
        last = max(dates) if dates else opened
        rows.append(
            {
                "case": d.name,
                "stem": _case_stem(d.name),
                "grade": (triage.get("grade") or "") or None,
                "status": (triage.get("status") or "") or None,
                "url": str(triage.get("url") or ""),
                "outcome": outcome or None,
                "takeover_dir": takeover,
                "close_files": close_files,
                "close": close,
                "opened": opened.isoformat() if opened else "",
                "last": last.isoformat() if last else "",
                "root_entries": len(root_files),
                "has_triage": bool(triage.get("case") or triage.get("grade")),
            }
        )
    return rows


def _by_site() -> set[str]:
    if not BY_SITE.is_dir():
        return set()
    return {
        p.name.lower()
        for p in BY_SITE.iterdir()
        if p.is_dir() and not p.name.startswith("_") and not p.name.startswith(".")
    }


def _success_sites() -> set[str]:
    try:
        from success_report_index import report_dirs, normalize_name
    except ImportError:
        return set()
    out: set[str] = set()
    try:
        for outcome, _tech, site in report_dirs():
            if "失败" in outcome or "未" in outcome:
                continue
            out.add(site.name.lower())
            out.add(normalize_name(site.name))
    except OSError:
        return set()
    return out


def _age_days(iso: str) -> int | None:
    if not iso:
        return None
    try:
        d = date.fromisoformat(iso[:10])
    except ValueError:
        return None
    return (TODAY - d).days


def classify_case(row: dict[str, Any], keep_stems: set[str]) -> str:
    if row.get("close"):
        return "KEEP_CLOSE"
    if row["stem"] in keep_stems:
        return "KEEP_KNOWN"
    last_age = _age_days(row.get("last") or "")
    opened_age = _age_days(row.get("opened") or "")
    oneshot = False
    if row.get("opened") and row.get("last"):
        try:
            gap = (
                date.fromisoformat(row["last"][:10])
                - date.fromisoformat(row["opened"][:10])
            ).days
            oneshot = gap <= 2 and (opened_age or 0) > COOL_DAYS
        except ValueError:
            oneshot = False
    if oneshot:
        return "STALE_ONESHOT"
    if last_age is None and opened_age and opened_age > COLD_DAYS:
        return "STALE_ONESHOT"
    if last_age is None:
        return "STALE_UNKNOWN"
    if last_age <= COOL_DAYS:
        return "RECENT"
    if last_age <= COLD_DAYS:
        return "COOL"
    return "STALE"


def snapshot() -> dict[str, Any]:
    sites = _load_sites()
    cases = _load_cases()
    by_site = _by_site()
    success = _success_sites()
    keep_stems = by_site | success | {c["stem"] for c in cases if c.get("close")}

    for c in cases:
        c["bucket"] = classify_case(c, keep_stems)

    cases_by_stem = defaultdict(list)
    for c in cases:
        cases_by_stem[c["stem"]].append(c["case"])

    families: dict[str, dict[str, Any]] = {}
    for s in sites:
        root = s["root"] or s["name"] or s["file"]
        fam = families.setdefault(
            root,
            {
                "root": root,
                "n_scope": 0,
                "names": [],
                "cases_linked": set(),
                "added": [],
                "notes": [],
            },
        )
        fam["n_scope"] += 1
        if s["name"] and s["name"] not in fam["names"] and len(fam["names"]) < 8:
            fam["names"].append(s["name"])
        if s["case"]:
            fam["cases_linked"].add(s["case"])
        if s["added"]:
            fam["added"].append(s["added"])
        if s["note"] and len(fam["notes"]) < 2:
            fam["notes"].append(s["note"])

    fam_rows = []
    for root, fam in families.items():
        linked = sorted(fam["cases_linked"])
        root_slug = root.replace(".", "_").replace("-", "_").lower()
        matched = list(cases_by_stem.get(root_slug, []))
        for c in cases:
            if c["case"] in linked and c["case"] not in matched:
                matched.append(c["case"])
        case_meta = [c for c in cases if c["case"] in set(linked) | set(matched)]
        buckets = {c["bucket"] for c in case_meta}
        last = ""
        for c in case_meta:
            if c["last"] > last:
                last = c["last"]
        added = max(fam["added"]) if fam["added"] else ""
        if case_meta and any(b.startswith("KEEP") for b in buckets):
            fb = "KEEP"
        elif case_meta and "RECENT" in buckets:
            fb = "RECENT"
        elif case_meta and any(b.startswith("STALE") or b == "COOL" for b in buckets):
            fb = "STALE_CASE"
        elif not case_meta:
            age_add = _age_days(added)
            fb = "GRANT_ONLY" if (age_add is None or age_add > COOL_DAYS) else "GRANT_NEW"
        else:
            fb = "REVIEW"
        fam_rows.append(
            {
                "root": root,
                "n_scope": fam["n_scope"],
                "names": fam["names"],
                "cases": sorted(set(linked) | set(matched)),
                "last": last,
                "added": added,
                "bucket": fb,
                "note": (fam["notes"][0] if fam["notes"] else "")[:60],
            }
        )

    stale_cases = [
        c
        for c in cases
        if c["bucket"] in {"STALE", "STALE_ONESHOT", "STALE_UNKNOWN", "COOL"}
    ]
    keep_cases = [c for c in cases if str(c["bucket"]).startswith("KEEP")]
    recent_cases = [c for c in cases if c["bucket"] == "RECENT"]
    stale_fams = [f for f in fam_rows if f["bucket"] == "STALE_CASE"]
    grant_only = [f for f in fam_rows if f["bucket"] == "GRANT_ONLY"]
    keep_fams = [f for f in fam_rows if f["bucket"] == "KEEP"]

    return {
        "as_of": TODAY.isoformat(),
        "cold_days": COLD_DAYS,
        "counts": {
            "scope_files": len(sites),
            "families": len(fam_rows),
            "cases": len(cases),
            "stale_cases": len(stale_cases),
            "cool_or_stale_cases": len(stale_cases),
            "keep_cases": len(keep_cases),
            "recent_cases": len(recent_cases),
            "stale_families": len(stale_fams),
            "grant_only_families": len(grant_only),
            "keep_families": len(keep_fams),
            "by_site": len(by_site),
            "success_index": len(success),
        },
        "stale_cases": sorted(stale_cases, key=lambda x: (x.get("last") or "", x["case"])),
        "keep_cases": sorted(keep_cases, key=lambda x: x["case"]),
        "recent_cases": sorted(recent_cases, key=lambda x: x["case"]),
        "stale_families": sorted(stale_fams, key=lambda x: (-x["n_scope"], x["root"])),
        "grant_only_families": sorted(grant_only, key=lambda x: (-x["n_scope"], x["root"])),
        "keep_families": sorted(keep_fams, key=lambda x: x["root"]),
        "by_site": sorted(by_site),
    }


def _plan(data: dict[str, Any]) -> dict[str, Any]:
    """七月 + 8/1–15 案卷，以及无案卷授权族。保护 keep/recent。"""
    keep = {c["case"] for c in data["keep_cases"]}
    recent = {c["case"] for c in data["recent_cases"]}
    keep_stems = {c["stem"] for c in data["keep_cases"] + data["recent_cases"]}
    keep_roots = {f["root"] for f in data["keep_families"]}
    archive: list[str] = []
    for c in data["stale_cases"]:
        if c["case"] in keep or c["case"] in recent or c["stem"] in keep_stems:
            continue
        opened = c.get("opened") or ""
        if opened.startswith("2026-07") or (opened and opened < "2026-08-16"):
            archive.append(c["case"])
    archive_stems = {_case_stem(n) for n in archive}
    grant_roots = {
        f["root"]
        for f in data["grant_only_families"]
        if f["root"] not in keep_roots
    }
    sites = _load_sites()
    drop_files: list[str] = []
    skip_files: list[str] = []
    for s in sites:
        stems = set()
        if s.get("case"):
            stems.add(_case_stem(s["case"]))
        if s.get("site_id"):
            stems.add(s["site_id"].lower())
        if s.get("name"):
            stems.add(s["name"].lower().replace(".", "_"))
        if s.get("root") and s["root"] not in {"IP", "INFRA"}:
            stems.add(s["root"].split(".")[0].lower())
            stems.add(s["root"].replace(".", "_").lower())
        protected = (
            s.get("case") in keep
            or s.get("case") in recent
            or s.get("root") in keep_roots
            or bool(stems & keep_stems)
        )
        if protected:
            skip_files.append(s["file"])
            continue
        hit = (
            s.get("case") in archive
            or s.get("root") in grant_roots
            or bool(stems & archive_stems)
        )
        if hit:
            drop_files.append(s["file"])
    return {
        "archive_cases": sorted(set(archive)),
        "drop_scope_files": sorted(set(drop_files)),
        "skip_scope_files": sorted(set(skip_files)),
        "grant_roots": sorted(grant_roots),
        "protected_cases": sorted(keep | recent),
    }


def _revoke_company(dropped_sites: list[dict[str, Any]], kept_sites: list[dict[str, Any]]) -> dict[str, int]:
    """从总表拿掉已删单站对应的 target，不打印正文。"""
    if not COMPANY.is_file():
        return {"before": 0, "after": 0, "removed": 0}
    kept_hosts: set[str] = set()
    kept_roots: set[str] = set()
    for s in kept_sites:
        if s.get("name"):
            kept_hosts.add(s["name"].lower())
        if s.get("root") and s["root"] not in {"IP", "INFRA"}:
            kept_roots.add(s["root"])
            kept_hosts.add(s["root"])
    drop_hosts: set[str] = set()
    drop_roots: set[str] = set()
    for s in dropped_sites:
        if s.get("name"):
            drop_hosts.add(s["name"].lower())
        if s.get("root") and s["root"] not in {"IP", "INFRA"}:
            drop_roots.add(s["root"])
    company = load_json(COMPANY)
    before = list(company.get("targets") or [])
    kept_targets: list[str] = []
    removed = 0
    for raw in before:
        if not isinstance(raw, str) or not raw.strip():
            continue
        t = raw.strip()
        h = (target_host(t) or host_of(t) or t).lower().lstrip("*.")
        root = "IP" if _looks_ipv4(h) else registrable_guess(h)
        still_kept = h in kept_hosts or root in kept_roots
        doomed = (h in drop_hosts or root in drop_roots) and not still_kept
        if doomed:
            removed += 1
            continue
        kept_targets.append(t)
    company["targets"] = kept_targets
    save_json(COMPANY, company)
    compact_company()
    after = len(load_json(COMPANY).get("targets") or [])
    return {"before": len(before), "after": after, "removed": removed}


def prune(*, apply: bool) -> dict[str, Any]:
    data = snapshot()
    plan = _plan(data)
    dest_root = CASES / "_archive" / f"stale_{TODAY.isoformat().replace('-', '')}"
    report = {
        "as_of": TODAY.isoformat(),
        "apply": apply,
        "archive_to": str(dest_root.relative_to(ENGINE)),
        "archive_cases": len(plan["archive_cases"]),
        "drop_scope": len(plan["drop_scope_files"]),
        "skip_scope": len(plan["skip_scope_files"]),
        "moved": [],
        "deleted_scope": [],
        "company": {},
    }
    if not apply:
        return report

    dest_root.mkdir(parents=True, exist_ok=True)
    for name in plan["archive_cases"]:
        src = CASES / name
        if not src.is_dir():
            continue
        dest = dest_root / name
        if dest.exists():
            dest = dest_root / f"{name}_dup"
        shutil.move(str(src), str(dest))
        report["moved"].append(name)

    dropped_meta = []
    sites_by_file = {s["file"]: s for s in _load_sites()}
    for fn in plan["drop_scope_files"]:
        p = SITES / fn
        if not p.is_file():
            continue
        dropped_meta.append(sites_by_file.get(fn) or {"file": fn})
        p.unlink()
        report["deleted_scope"].append(fn)

    kept_sites = _load_sites()
    report["company"] = _revoke_company(dropped_meta, kept_sites)
    manifest = dest_root / "PRUNE_MANIFEST.json"
    manifest.write_text(
        json.dumps(
            {
                "as_of": TODAY.isoformat(),
                "moved": report["moved"],
                "deleted_scope": report["deleted_scope"],
                "company": report["company"],
                "protected_cases": plan["protected_cases"],
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return report


def _sensitive(data: dict[str, Any]) -> bool:
    return any(data.get(k) for k in SENSITIVE_KEYS)


def _union_domains(datas: list[dict[str, Any]]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for data in datas:
        for raw in list(data.get("domains") or []) + [data.get("name") or ""]:
            h = str(raw or "").strip().lower().rstrip(".")
            if not h or h in seen:
                continue
            seen.add(h)
            out.append(h)
    return sorted(out)


def _pick_keeper(root: str, rows: list[tuple[Path, dict[str, Any]]]) -> Path:
    slug = root.replace(".", "_").replace("-", "_")
    prefer = f"scope.{slug}.json"
    for p, _d in rows:
        if p.name == prefer:
            return p
    return max(rows, key=lambda pd: (len(pd[1].get("domains") or []), pd[0].name))[0]


def compact_plan() -> dict[str, Any]:
    """同根合并 + 丢掉 INFRA + 丢掉无 KEEP/RECENT 保护的 IP。不删仍在打的家族。"""
    data = snapshot()
    plan = _plan(data)
    keep = set(plan["protected_cases"])
    keep_stems = {c["stem"] for c in data["keep_cases"] + data["recent_cases"]}
    sites = _load_sites()
    by_root: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in sites:
        by_root[row["root"] or row["name"] or row["file"]].append(row)

    merge: list[dict[str, Any]] = []
    drop: list[str] = []
    keep_files: list[str] = []
    for root, rows in by_root.items():
        if root == "INFRA":
            drop.extend(r["file"] for r in rows)
            continue
        if root == "IP":
            for r in rows:
                protected = (
                    r.get("case") in keep
                    or _case_stem(r.get("case") or "") in keep_stems
                )
                if protected:
                    keep_files.append(r["file"])
                else:
                    drop.append(r["file"])
            continue
        if len(rows) == 1:
            keep_files.append(rows[0]["file"])
            continue
        paths = []
        for r in rows:
            p = SITES / r["file"]
            paths.append((p, _safe_json(p)))
        sensitive = [(p, d) for p, d in paths if _sensitive(d)]
        normal = [(p, d) for p, d in paths if not _sensitive(d)]
        for p, _d in sensitive:
            keep_files.append(p.name)
        if not normal:
            continue
        keeper = _pick_keeper(root, normal)
        extras = [p.name for p, _d in normal if p.name != keeper.name]
        if extras:
            merge.append(
                {
                    "root": root,
                    "keeper": keeper.name,
                    "drop": extras,
                    "n": len(normal),
                }
            )
            keep_files.append(keeper.name)
        else:
            keep_files.append(keeper.name)
    return {
        "as_of": TODAY.isoformat(),
        "merge": sorted(merge, key=lambda x: -len(x["drop"])),
        "drop": sorted(set(drop)),
        "keep": sorted(set(keep_files)),
        "counts": {
            "merge_roots": len(merge),
            "merge_drop": sum(len(x["drop"]) for x in merge),
            "drop": len(set(drop)),
            "keep": len(set(keep_files)),
            "projected": len(set(keep_files)),
        },
    }


def compact_sites(*, apply: bool) -> dict[str, Any]:
    plan = compact_plan()
    dest = SITES / "_archive" / f"compact_{TODAY.isoformat().replace('-', '')}"
    report = {
        "as_of": TODAY.isoformat(),
        "apply": apply,
        "archive_to": str(dest.relative_to(ENGINE)),
        "counts": plan["counts"],
        "moved": [],
        "merged": [],
        "company": {},
    }
    if not apply:
        return report

    dest.mkdir(parents=True, exist_ok=True)
    dropped_meta: list[dict[str, Any]] = []
    sites_by_file = {s["file"]: s for s in _load_sites()}

    for item in plan["merge"]:
        keeper_p = SITES / item["keeper"]
        if not keeper_p.is_file():
            continue
        datas = [_safe_json(keeper_p)]
        moved = []
        for fn in item["drop"]:
            src = SITES / fn
            if not src.is_file():
                continue
            datas.append(_safe_json(src))
            dest_p = dest / fn
            if dest_p.exists():
                dest_p = dest / f"{src.stem}_dup{src.suffix}"
            shutil.move(str(src), str(dest_p))
            moved.append(fn)
            report["moved"].append(fn)
        keeper = dict(datas[0])
        keeper["domains"] = _union_domains(datas)
        if not keeper.get("name"):
            keeper["name"] = item["root"]
        keeper["compacted"] = {
            "at": TODAY.isoformat(),
            "n": 1 + len(moved),
            "from": moved,
        }
        save_json(keeper_p, keeper)
        report["merged"].append({"root": item["root"], "keeper": item["keeper"], "n": len(moved)})

    for fn in plan["drop"]:
        src = SITES / fn
        if not src.is_file():
            continue
        dropped_meta.append(sites_by_file.get(fn) or {"file": fn})
        dest_p = dest / fn
        if dest_p.exists():
            dest_p = dest / f"{src.stem}_dup{src.suffix}"
        shutil.move(str(src), str(dest_p))
        report["moved"].append(fn)

    kept_sites = _load_sites()
    report["company"] = _revoke_company(dropped_meta, kept_sites)
    compact_company()
    (dest / "COMPACT_MANIFEST.json").write_text(
        json.dumps(
            {
                "as_of": TODAY.isoformat(),
                "counts": plan["counts"],
                "merged": report["merged"],
                "moved": report["moved"],
                "company": report["company"],
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return report


def _print(data: dict[str, Any]) -> None:
    c = data["counts"]
    print(f"授权精简候选  as_of={data['as_of']}  冷>{data['cold_days']}天")
    print(
        f"scope_files={c['scope_files']} families={c['families']} "
        f"cases={c['cases']}"
    )
    print(
        f"stale_cases={c['stale_cases']} recent={c['recent_cases']} "
        f"keep={c['keep_cases']}"
    )
    print(
        f"stale_families={c['stale_families']} "
        f"grant_only_families={c['grant_only_families']} "
        f"keep_families={c['keep_families']}"
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="Scope/case stale candidates")
    ap.add_argument(
        "cmd", nargs="?", default="snapshot", choices=("snapshot", "prune", "compact")
    )
    ap.add_argument("--json", dest="json_out", default="")
    ap.add_argument("--apply", action="store_true", help="prune/compact：真正搬文件")
    args = ap.parse_args()
    if args.cmd == "compact":
        report = compact_sites(apply=args.apply)
        c = report["counts"]
        print(
            f"compact apply={int(args.apply)} "
            f"merge_roots={c['merge_roots']} merge_drop={c['merge_drop']} "
            f"drop={c['drop']} keep={c['keep']} projected={c['projected']}"
        )
        if args.apply:
            print(
                f"moved={len(report['moved'])} merged={len(report['merged'])} "
                f"company={report.get('company')}"
            )
            print(f"[+] {report['archive_to']}/COMPACT_MANIFEST.json")
        return 0
    if args.cmd == "prune":
        report = prune(apply=args.apply)
        print(
            f"prune apply={int(args.apply)} "
            f"archive_cases={report['archive_cases']} "
            f"drop_scope={report['drop_scope']} "
            f"skip_scope={report['skip_scope']}"
        )
        if args.apply:
            print(
                f"moved={len(report['moved'])} "
                f"deleted_scope={len(report['deleted_scope'])} "
                f"company={report.get('company')}"
            )
            print(f"[+] {report['archive_to']}/PRUNE_MANIFEST.json")
        return 0
    data = snapshot()
    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(data, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"[+] json -> {args.json_out}")
    _print(data)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
