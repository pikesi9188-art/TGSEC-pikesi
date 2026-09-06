#!/usr/bin/env python3
"""HITCON ZeroDay 公开列表分类（只学手法，不扩厂商进 scope）。

harvest：拉公开页；被 CF 拦则 --seed。
classify / gap：把标题映射到本库 Skill，标出缺口。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, UTC
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

try:
    import requests
    requests.packages.urllib3.disable_warnings()  # type: ignore
except ImportError:
    print("[!] pip install requests", file=sys.stderr)
    sys.exit(1)

OPS = Path(__file__).resolve().parent
ROOT = (OPS.parent if (OPS.parent / "杀招").is_dir() else (OPS.parent if (OPS.parent / "杀招").is_dir() else OPS.parents[1]))
UA = "Mozilla/5.0 大爱仙尊-hitcon-zd-intel"
BASE = "https://zeroday.hitcon.org"
LIST_PATHS = (
    "/vulnerability/all",
    "/vulnerability/disclosed",
    "/vulnerability/patching",
    "/vulnerability",
)

# 标题关键词 → 手法族（先匹配先赢）
FAMILY_RULES: list[tuple[str, tuple[str, ...]]] = [
    ("ollama_unauth", ("ollama",)),
    ("php_cgi_4577", ("cve-2024-4577", "php-cgi", "php cgi")),
    ("wp_xmlrpc", ("xmlrpc", "pingback", "multicall")),
    ("wp_webshell", ("wp2shell", "webshell", "後門", "后门", "已遭植入")),
    ("sqli", ("sql injection", "sqli", "sql 注入", "sql注入", "資料庫注入", "数据库注入")),
    ("wordpress", ("wordpress", "wp ", " wp")),
    ("weak_password", ("弱密碼", "弱密码", "弱口", "default password")),
    ("path_traversal", ("目錄遍歷", "目录遍历", "路徑穿越", "路径穿越", "lfi", "任意檔案", "任意文件")),
    ("idor_bola", ("idor", "bola", "越權", "越权", "僅用", "只用使用者", "使用者id", "權限管理失效", "权限管理失效")),
    ("client_state", ("驗證狀態", "客户端窜改", "用戶端竄改", "免費騎乘", "逻辑漏洞", "邏輯漏洞")),
    ("open_redirect", ("開放重定向", "开放重定向", "開放轉址", "开放转址", "returnurl")),
    ("waf_origin", ("origin ip", "akamai waf", "waf 繞過", "waf 绕过", "waf完全")),
    ("session_fixation", ("session fixation", "會話固定", "会话固定")),
    ("reset_token_leak", ("重設 token", "重置 token", "password reset", "token 外洩")),
    ("key_space", ("金鑰空間", "密钥空间", "key space", "永久盜用", "永久盗用")),
    ("ip_spoof", ("ip 偽造", "ip伪造", "xff", "x-forwarded-for")),
    ("dir_listing", ("目錄開放", "目录开放", "directory listing", ".log")),
    ("xss", ("xss", "跨站")),
    ("rce", ("rce", "遠端命令", "远程命令", "命令執行", "命令执行")),
    ("cctv", ("監視器", "监视器", "監視系統", "cctv")),
    ("paid_content", ("付費", "付费", "電子書", "电子书")),
]

SKILL_MAP: dict[str, dict[str, str]] = {
    "ollama_unauth": {
        "skill": "羊驼无门",
        "playbook": "传承/羊驼·无门.md",
        "grade": "P0",
    },
    "php_cgi_4577": {
        "skill": "幻页·门廊",
        "playbook": "传承/门廊·开天.md",
        "grade": "P0",
    },
    "wp_xmlrpc": {
        "skill": "坞·旧令",
        "playbook": "传承/坞·旧令.md",
        "grade": "P1",
    },
    "wp_webshell": {
        "skill": "坞壳落子猎",
        "playbook": "传承/坞壳落子猎.md",
        "grade": "P1",
        "note": "已落地马走高熵狩猎，勿把情报域扩权",
    },
    "client_state": {
        "skill": "客器",
        "playbook": "传承/客器·跳步.md",
        "grade": "P0",
        "note": "客户端 verified/paid 不可信；先验后端",
    },
    "dir_listing": {
        "skill": "搜魂蛊",
        "playbook": "传承/搜魂蛊.md",
        "grade": "P1",
    },
    "session_fixation": {
        "skill": "夺舍·票面",
        "playbook": "传承/夺舍·短票.md",
        "grade": "P1",
    },
    "reset_token_leak": {
        "skill": "夺舍·票面",
        "playbook": "传承/夺舍·短票.md",
        "grade": "P1",
    },
    "key_space": {
        "skill": "夺舍·票面",
        "playbook": "传承/夺舍·短票.md",
        "grade": "P1",
        "note": "短 token / 可预测重置走本卡",
    },
    "wordpress": {
        "skill": "坞·插件",
        "playbook": "传承/坞·接管.md",
        "grade": "P1",
    },
    "sqli": {
        "skill": "薄青·伤匣",
        "playbook": "传承/薄青·岁岁索命.md",
        "grade": "P1",
    },
    "weak_password": {
        "skill": "黑楼兰·硬撼",
        "playbook": "传承/薄青·岁岁索命.md",
        "grade": "P1",
    },
    "path_traversal": {
        "skill": "开卷",
        "playbook": "传承/薄青·岁岁索命.md",
        "grade": "P1",
    },
    "idor_bola": {
        "skill": "万我·横夺",
        "playbook": "传承/万我.md",
        "grade": "P0",
    },
    "open_redirect": {
        "skill": "暗渡陈仓",
        "playbook": "传承/暗渡陈仓·2.md",
        "grade": "P1",
    },
    "waf_origin": {
        "skill": "云帷",
        "playbook": "传承/云帷·源溯.md",
        "grade": "P1",
    },
    "ip_spoof": {
        "skill": "信头·踪",
        "playbook": "传承/信头·踪.md",
        "grade": "P0",
    },
    "xss": {
        "skill": "薄青·伤匣",
        "playbook": "传承/薄青·岁岁索命.md",
        "grade": "P2",
    },
    "rce": {
        "skill": "一日针匣",
        "playbook": "传承/新伤·在野.md",
        "grade": "P0",
    },
    "cctv": {
        "skill": "",
        "playbook": "",
        "grade": "skip",
        "note": "监视器面不作为网站案主线",
    },
    "paid_content": {
        "skill": "万我·横夺",
        "playbook": "传承/万我.md",
        "grade": "P1",
    },
}

ZD_RE = re.compile(
    r"(ZD-\d{4}-\d{5}).{0,240}?(?:Risk|風險|风险)[:：\s]*([^\n<]{1,12})"
    r".{0,120}?(?:Status|狀態|状态)[:：\s]*([^\n<]{1,20})"
    r".{0,80}?(?:Date|日期)[:：\s]*(\d{4}/\d{2}/\d{2})",
    re.I | re.S,
)
TITLE_RE = re.compile(r"(?:####\s*|Title[:：]\s*)([^\n#]{4,120})")
H4_RE = re.compile(
    r'<h4[^>]*class="[^"]*title[^"]*"[^>]*>\s*([^<]{4,160})\s*</h4>',
    re.I,
)
HREF_ZD_RE = re.compile(
    r'href="(/vulnerability/(ZD-\d{4}-\d{5}))"[^>]*>\s*(?:<[^>]+>\s*)*([^<]{4,160})',
    re.I,
)
CODE_RE = re.compile(r"(ZD-\d{4}-\d{5})")
DIRTY_TITLE = ("onclick", "data-cf-modified", "class=\"title", "urn false")


def _clean_title(s: str) -> str:
    t = re.sub(r"\s+", " ", (s or "")).strip()
    if any(d in t.lower() for d in DIRTY_TITLE):
        return ""
    return t[:160]


def _parse_html(html: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for m in HREF_ZD_RE.finditer(html):
        zd, title = m.group(2), _clean_title(m.group(3))
        if zd in seen or not title:
            continue
        seen.add(zd)
        rows.append(_row(zd, title))
    if rows:
        return rows
    for m in H4_RE.finditer(html):
        title = _clean_title(m.group(1))
        if not title:
            continue
        chunk = html[m.start() : m.start() + 800]
        zm = CODE_RE.search(chunk)
        if not zm or zm.group(1) in seen:
            continue
        seen.add(zm.group(1))
        rows.append(_row(zm.group(1), title))
    if rows:
        return rows
    for m in ZD_RE.finditer(html):
        zd, risk, status, date = m.group(1), m.group(2), m.group(3), m.group(4)
        if zd in seen:
            continue
        chunk = html[max(0, m.start() - 400) : m.start()]
        titles = [_clean_title(t) for t in TITLE_RE.findall(chunk)]
        title = next((t for t in reversed(titles) if t), "")
        if not title:
            continue
        seen.add(zd)
        rows.append(_row(zd, title, risk, status, date))
    return rows


def classify_families(title: str) -> list[str]:
    t = (title or "").lower()
    raw = title or ""
    hits: list[str] = []
    for family, keys in FAMILY_RULES:
        for k in keys:
            if k.lower() in t or k in raw:
                hits.append(family)
                break
    return hits or ["other"]


def classify_title(title: str) -> str:
    return classify_families(title)[0]


def _row(zd: str, title: str, risk: str = "", status: str = "", date: str = "") -> dict[str, Any]:
    families = classify_families(title)
    family = families[0]
    mapped = SKILL_MAP.get(family, {"skill": "", "playbook": "", "grade": "gap"})
    skills = []
    for fam in families:
        sk = (SKILL_MAP.get(fam) or {}).get("skill") or ""
        if sk and sk not in skills:
            skills.append(sk)
    return {
        "zd": zd,
        "title": title[:160],
        "risk": risk.strip(),
        "status": status.strip(),
        "date": date,
        "family": family,
        "families": families,
        "skill": mapped.get("skill", ""),
        "skills": skills,
        "playbook": mapped.get("playbook", ""),
        "grade": mapped.get("grade", "gap"),
        "note": mapped.get("note", ""),
        "vendor_in_scope": False,
    }


def _merge_items(seed: list[dict[str, Any]], live: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_zd: dict[str, dict[str, Any]] = {}
    for it in seed + live:
        zd = it.get("zd") or ""
        if not zd:
            continue
        old = by_zd.get(zd)
        if not old:
            by_zd[zd] = it
            continue
        old_title = old.get("title") or ""
        new_title = it.get("title") or ""
        old_dirty = (not old_title) or old.get("family") == "other"
        new_ok = bool(new_title) and it.get("family") != "other"
        if old_dirty and new_ok:
            by_zd[zd] = it
            continue
        if len(new_title) > len(old_title) and it.get("family") != "other":
            merged = dict(old)
            merged.update({k: it[k] for k in ("title", "family", "families", "skill", "skills", "playbook", "grade", "note") if k in it})
            by_zd[zd] = merged
    return list(by_zd.values())


def _fetch_lists(timeout: int = 20) -> tuple[list[dict[str, Any]], list[str]]:
    sess = requests.Session()
    sess.verify = False
    sess.headers["User-Agent"] = UA
    rows: list[dict[str, Any]] = []
    errors: list[str] = []
    seen: set[str] = set()
    for path in LIST_PATHS:
        url = urljoin(BASE + "/", path.lstrip("/"))
        try:
            r = sess.get(url, timeout=timeout, verify=True)
        except Exception as e:
            errors.append(f"{path}: {e}")
            continue
        if r.status_code != 200 or "security verification" in (r.text or "").lower():
            errors.append(f"{path}: http {r.status_code} cf_or_empty")
            continue
        for row in _parse_html(r.text or ""):
            if row["zd"] in seen:
                continue
            seen.add(row["zd"])
            rows.append(row)
    return rows, errors


def _load_seed(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    items = data.get("items") or data.get("reports") or data
    if not isinstance(items, list):
        raise SystemExit(f"[!] seed 无 items: {path}")
    out: list[dict[str, Any]] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        title = str(it.get("title") or it.get("zd") or "")
        out.append(
            _row(
                str(it.get("zd") or ""),
                title,
                str(it.get("risk") or ""),
                str(it.get("status") or ""),
                str(it.get("date") or ""),
            )
        )
    return [r for r in out if r["zd"]]


def _report(items: list[dict[str, Any]], source: str, errors: list[str]) -> dict[str, Any]:
    families: dict[str, int] = {}
    gaps: list[str] = []
    for it in items:
        fam = it["family"]
        families[fam] = families.get(fam, 0) + 1
        if it["grade"] in {"gap", ""} or (fam == "other"):
            gaps.append(it["zd"])
    return {
        "ts": datetime.now(UTC).isoformat(),
        "source": source,
        "site": BASE,
        "count": len(items),
        "families": dict(sorted(families.items(), key=lambda kv: (-kv[1], kv[0]))),
        "gap_zds": gaps[:40],
        "errors": errors,
        "redline": "禁止把通报 Vendor 写入 scope；手法可复用，域名须另有授权",
        "items": items,
    }


def cmd_harvest(args: argparse.Namespace) -> int:
    live, errors = _fetch_lists()
    seed_path = Path(args.seed) if args.seed else ROOT / "docs/intel/hitcon-zeroday/2026-08-27.json"
    seed = _load_seed(seed_path) if seed_path.is_file() else []
    if live and seed:
        items = _merge_items(seed, live)
        source = "live+seed"
    elif live:
        items = live
        source = "live"
    elif seed:
        items = seed
        source = f"seed:{seed_path}"
        errors.append("live empty; used seed")
    else:
        print("[!] 公开页被拦且无 seed", file=sys.stderr)
        return 2
    report = _report(items, source, errors)
    out = Path(args.out) if args.out else ROOT / "docs/intel/hitcon-zeroday" / f"{datetime.now():%Y-%m-%d}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"count": report["count"], "source": source, "families": report["families"], "out": str(out)}, ensure_ascii=False))
    return 0


def cmd_classify(args: argparse.Namespace) -> int:
    items = _load_seed(Path(args.seed))
    report = _report(items, f"classify:{args.seed}", [])
    print(json.dumps({"count": report["count"], "families": report["families"], "gap_zds": report["gap_zds"]}, ensure_ascii=False, indent=2))
    return 0


DOCTOR_CASES: list[tuple[str, list[str]]] = [
    ("後台 SQL Injection", ["sqli"]),
    ("Wordpress SQL Injection", ["sqli", "wordpress"]),
    ("xmlrpc.php暴露", ["wp_xmlrpc"]),
    ("CVE-2024-4577", ["php_cgi_4577"]),
    ("Ollama 服務未授權", ["ollama_unauth"]),
    ("驗證狀態可由用戶端竄改", ["client_state"]),
    ("機敏資料目錄開放瀏覽", ["dir_listing"]),
    ("Origin IP 洩露導致 Akamai WAF 完全繞過", ["waf_origin"]),
    ("XSS 注入", ["xss"]),
    ("SQL Injection 漏洞與 IP 偽造", ["sqli", "ip_spoof"]),
    ("wp2shell", ["wp_webshell"]),
    ("開放重定向 returnUrl", ["open_redirect"]),
]


def cmd_doctor(_args: argparse.Namespace) -> int:
    bad: list[str] = []
    for title, expect in DOCTOR_CASES:
        got = classify_families(title)
        if not set(expect).issubset(set(got)):
            bad.append(f"{title!r} expect {expect} got {got}")
        if got and got[0] != expect[0]:
            bad.append(f"{title!r} primary {got[0]} != {expect[0]}")
        if "xss" in expect and "sqli" in got:
            bad.append(f"{title!r} xss must not also be sqli")
    if bad:
        print(json.dumps({"ok": False, "fail": bad}, ensure_ascii=False, indent=2))
        return 1
    print(json.dumps({"ok": True, "cases": len(DOCTOR_CASES)}, ensure_ascii=False))
    return 0


def cmd_gap(args: argparse.Namespace) -> int:
    items = _load_seed(Path(args.seed))
    skills_root = ROOT / ".cursor/skills"
    missing: list[dict[str, Any]] = []
    seen_fam: set[str] = set()
    for it in items:
        fam = it["family"]
        if fam in seen_fam:
            continue
        seen_fam.add(fam)
        skill = it.get("skill") or ""
        exists = bool(skill) and (skills_root / skill / "SKILL.md").is_file()
        if not exists and it.get("grade") != "skip":
            missing.append({"family": fam, "skill": skill or "(none)", "example_zd": it["zd"], "grade": it.get("grade")})
    print(json.dumps({"missing_skills": missing, "families_seen": sorted(seen_fam)}, ensure_ascii=False, indent=2))
    return 0


def main() -> None:
    ap = argparse.ArgumentParser(description="HITCON ZeroDay 公开列表分类（不扩厂商）")
    sub = ap.add_subparsers(dest="cmd", required=True)
    h = sub.add_parser("harvest", help="拉公开列表；失败回退 seed")
    h.add_argument("--out", default="")
    h.add_argument("--seed", default="")
    c = sub.add_parser("classify", help="只分类已有 JSON")
    c.add_argument("--seed", required=True)
    g = sub.add_parser("gap", help="对照 .cursor/skills 标缺口")
    g.add_argument("--seed", required=True)
    sub.add_parser("doctor", help="分类回归")
    args = ap.parse_args()
    if args.cmd == "harvest":
        raise SystemExit(cmd_harvest(args))
    if args.cmd == "classify":
        raise SystemExit(cmd_classify(args))
    if args.cmd == "doctor":
        raise SystemExit(cmd_doctor(args))
    raise SystemExit(cmd_gap(args))


if __name__ == "__main__":
    main()
