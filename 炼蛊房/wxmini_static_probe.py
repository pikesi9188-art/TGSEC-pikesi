#!/usr/bin/env python3
"""微信小程序静态审计（授权内）。

对齐 Playbook：传承/微域·静审.md
Skill：杀招/微域

默认只读本地目录 / wxapkg。抽出 URL 打 in_scope；--probe-urls 才 GET。
禁止把 JSON 写回源码目录。vendor 扫描器必须 --output。

流水线（对方 7 Agent → 本库三刀）：
  scan     Phase 1+1.5  inventory / raw_* / summary
  analyze  Phase 2      secrets_report / api_endpoints / crypto / vuln
  report   Phase 3      security_report.md + 全量 md
  run      三刀连打（默认入口）
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, UTC
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

OPS = Path(__file__).resolve().parent
ENGINE = (OPS.parent if (OPS.parent / "杀招").is_dir() else (OPS.parent if (OPS.parent / "杀招").is_dir() else OPS.parents[1]))
WXMINI = ENGINE / "tools" / "wxmini"
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import host_of, in_scope, write_probe_json  # noqa: E402

PLAYBOOK = "传承/微域·静审.md"
SECRET_PY = WXMINI / "secret_scanner.py"
ENDPOINT_PY = WXMINI / "endpoint_extractor.py"
SKIP_HOST_SUFFIX = (
    "weixin.qq.com",
    "servicewechat.com",
    "qlogo.cn",
    "qpic.cn",
    "gtimg.cn",
    "idqqimg.com",
)
SCAN_EXT = {
    ".js": "js_files",
    ".ts": "js_files",
    ".json": "json_files",
    ".wxml": "wxml_files",
    ".wxss": "wxss_files",
}
EXCLUDE_DIR = {".git", "node_modules", "__pycache__"}

CRYPTO_PATS: list[tuple[str, str, str]] = [
    ("cryptojs-aes", r"CryptoJS\.AES", "High"),
    ("cryptojs-des", r"CryptoJS\.(?:DES|TripleDES)", "High"),
    ("cryptojs-mode-ecb", r"CryptoJS\.mode\.ECB|mode:\s*['\"]ECB", "High"),
    ("jsencrypt", r"new\s+JSEncrypt|setPrivateKey\s*\(", "Critical"),
    ("sm-crypto", r"sm2\.doEncrypt|sm4\.encrypt|miniprogram-sm-crypto", "High"),
    ("forge", r"forge\.(?:cipher|pki)\.", "Medium"),
    ("subtle", r"crypto\.subtle", "Info"),
    ("hardcoded-pem", r"-----BEGIN (?:RSA )?PRIVATE KEY-----", "Critical"),
    ("hardcoded-iv", r"(?i)(?:iv|IV)\s*[:=]\s*['\"][A-Za-z0-9+/=]{8,}['\"]", "High"),
]

VULN_PATS: list[tuple[str, str, str, str]] = [
    ("debug-true", r"(?:enableDebug|isDebug|debugMode)\s*[:=]\s*(?:true|1)", "High", "config"),
    ("vconsole", r"vconsole|eruda", "High", "config"),
    ("urlcheck-off", r"['\"]urlCheck['\"]\s*:\s*false", "Medium", "config"),
    ("http-request", r"wx\.(?:request|uploadFile|downloadFile)\s*\([\s\S]{0,200}http://", "High", "config"),
    ("storage-token", r"wx\.setStorage(?:Sync)?\s*\(\s*['\"][^'\"]*(?:token|session|password|openid)", "High", "data"),
    ("front-role", r"(?:isAdmin|role)\s*===?\s*['\"]admin['\"]", "High", "auth"),
    ("amount-client", r"wx\.requestPayment|totalFee|totalPrice|orderAmount", "High", "biz"),
    ("idor-path", r"/api/(?:user|order|member)/\$\{", "High", "biz"),
    ("webview-bind", r"<web-view[^>]+src\s*=\s*['\"]\{\{", "Critical", "webview"),
    ("cloud-fn", r"wx\.cloud\.callFunction", "Medium", "cloud"),
    ("sms-send", r"(?:sendSms|sendCode|smsCode|/sms/|/captcha/)", "Medium", "biz"),
]


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _is_under(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def _iter_source(root: Path) -> list[Path]:
    out: list[Path] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in EXCLUDE_DIR for part in p.parts):
            continue
        if p.suffix.lower() in SCAN_EXT:
            out.append(p)
    return out


def _find_wxapkg(root: Path) -> list[Path]:
    if root.is_file() and root.suffix.lower() == ".wxapkg":
        return [root]
    return [p for p in root.rglob("*.wxapkg") if p.is_file()]


def _try_unveilr(packs: list[Path], dest: Path) -> list[dict[str, Any]]:
    exe = shutil.which("unveilr") or shutil.which("unveilr.exe")
    rows: list[dict[str, Any]] = []
    if not exe:
        return [{"pack": str(p), "ok": False, "error": "unveilr 不在 PATH"} for p in packs]
    dest.mkdir(parents=True, exist_ok=True)
    for pack in packs:
        out_dir = dest / pack.stem
        out_dir.mkdir(parents=True, exist_ok=True)
        try:
            proc = subprocess.run(
                [exe, str(pack), "-o", str(out_dir)],
                capture_output=True,
                text=True,
                timeout=120,
            )
            rows.append(
                {
                    "pack": str(pack),
                    "ok": proc.returncode == 0,
                    "out": str(out_dir),
                    "rc": proc.returncode,
                    "err": (proc.stderr or "")[:200],
                }
            )
        except Exception as exc:
            rows.append({"pack": str(pack), "ok": False, "error": str(exc)[:160]})
    return rows


def write_inventory(root: Path, out: Path) -> dict[str, Any]:
    buckets: dict[str, list[str]] = defaultdict(list)
    for p in _iter_source(root):
        rel = str(p.relative_to(root))
        buckets[SCAN_EXT[p.suffix.lower()]].append(rel)
    packs = [str(p.relative_to(root) if _is_under(p, root) else p) for p in _find_wxapkg(root)]
    app_json = []
    for p in root.rglob("app.json"):
        if p.is_file() and "node_modules" not in p.parts:
            app_json.append(str(p.relative_to(root)))
    inv = {
        "ts": _now(),
        "target_dir": str(root),
        "file_inventory": {k: sorted(v) for k, v in buckets.items()},
        "wxapkg": packs,
        "app_json": app_json,
        "counts": {k: len(v) for k, v in buckets.items()},
    }
    (out / "file_inventory.json").write_text(
        json.dumps(inv, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return inv


def _scan_pats(
    root: Path, specs: list[tuple[str, str, str]] | list[tuple[str, str, str, str]]
) -> list[dict[str, Any]]:
    compiled = []
    for spec in specs:
        name, pat, sev = spec[0], spec[1], spec[2]
        dim = spec[3] if len(spec) == 4 else "crypto"
        compiled.append((name, re.compile(pat, re.I | re.M), sev, dim))
    hits: list[dict[str, Any]] = []
    for path in _iter_source(root):
        if path.stat().st_size > 2_000_000:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = str(path.relative_to(root))
        for name, rx, sev, dim in compiled:
            m = rx.search(text)
            if not m:
                continue
            hits.append(
                {
                    "name": name,
                    "dim": dim,
                    "severity": sev,
                    "file": rel,
                    "line": text[: m.start()].count("\n") + 1,
                    "snippet": text[max(0, m.start() - 20) : m.end() + 60].replace("\n", " ")[:160],
                }
            )
    return hits


def _hidden_pages(root: Path) -> list[dict[str, Any]]:
    needles = (
        "admin", "manage", "manager", "debug", "backdoor", "superadmin",
        "hidden", "operator",
    )
    found: list[dict[str, Any]] = []
    for p in root.rglob("app.json"):
        if not p.is_file() or "node_modules" in p.parts:
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8", errors="ignore"))
        except json.JSONDecodeError:
            continue
        pages = list(data.get("pages") or [])
        for sp in data.get("subpackages") or data.get("subPackages") or []:
            root_sp = str(sp.get("root") or "").rstrip("/")
            for pg in sp.get("pages") or []:
                pages.append(f"{root_sp}/{pg}" if root_sp else str(pg))
        for pg in pages:
            low = str(pg).lower()
            if any(n in low for n in needles):
                found.append({"file": str(p.relative_to(root)), "page": pg, "severity": "High"})
    return found


def _run_scanner(script: Path, target: Path, out: Path) -> None:
    cmd = [
        sys.executable,
        str(script),
        str(target),
        "--output",
        str(out),
        "--inventory",
        str(out / "file_inventory.json"),
    ]
    proc = subprocess.run(cmd, cwd=str(ENGINE), capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"{script.name} 失败 rc={proc.returncode}\n{proc.stdout}\n{proc.stderr}"
        )


def _hosts_from_endpoints(raw: dict[str, Any]) -> list[dict[str, Any]]:
    seen: dict[str, dict[str, Any]] = {}
    values: list[str] = []
    for hit in raw.get("all_hits") or []:
        values.append(str(hit.get("value") or hit.get("url") or ""))
    for bu in raw.get("base_url_candidates") or []:
        values.append(str(bu.get("value") or ""))
    for val in values:
        if "://" not in val and not val.startswith("//"):
            continue
        host = host_of(val) or (urlparse(val if "://" in val else "https:" + val).hostname or "")
        if not host:
            continue
        row = seen.setdefault(
            host, {"host": host, "in_scope": False, "samples": [], "skip_reason": ""}
        )
        if val and len(row["samples"]) < 5:
            row["samples"].append(val[:240])
    for host, row in seen.items():
        low = host.lower()
        if any(low == s or low.endswith("." + s) for s in SKIP_HOST_SUFFIX):
            row["skip_reason"] = "wechat-cdn"
            continue
        try:
            row["in_scope"] = bool(in_scope(host) or in_scope("https://" + host))
        except Exception:
            row["in_scope"] = False
    return sorted(seen.values(), key=lambda x: (not x["in_scope"], x["host"]))


def _fuzz_paths(raw: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    seen: set[str] = set()
    for hit in raw.get("all_hits") or []:
        val = str(hit.get("value") or "")
        if not val.startswith("/"):
            if "://" in val:
                path = urlparse(val).path or ""
                val = path
            else:
                continue
        if val and val not in seen and len(val) < 180:
            seen.add(val)
            paths.append(val)
    return sorted(paths)[:400]


def _probe_urls(hosts: list[dict[str, Any]], timeout: float = 8.0) -> list[dict[str, Any]]:
    try:
        import requests

        requests.packages.urllib3.disable_warnings()  # type: ignore
    except ImportError:
        return [{"error": "pip install requests"}]
    out: list[dict[str, Any]] = []
    for row in hosts:
        if not row.get("in_scope") or row.get("skip_reason"):
            continue
        url = row["samples"][0] if row["samples"] else f"https://{row['host']}/"
        if "://" not in url:
            url = "https://" + url.lstrip("/")
        try:
            r = requests.get(
                url,
                timeout=timeout,
                verify=False,
                allow_redirects=False,
                headers={"User-Agent": "Mozilla/5.0 大爱仙尊-wxmini"},
            )
            out.append(
                {
                    "host": row["host"],
                    "url": url[:240],
                    "status": r.status_code,
                    "len": len(r.content),
                }
            )
        except Exception as exc:
            out.append({"host": row["host"], "url": url[:240], "error": str(exc)[:160]})
    return out


def cmd_doctor() -> int:
    checks: list[dict[str, Any]] = []

    def add(name: str, ok: bool, detail: str) -> None:
        checks.append({"name": name, "ok": ok, "detail": detail})
        print(f"[{'OK' if ok else 'FAIL'}] {name}: {detail}")

    add("secret_scanner", SECRET_PY.is_file(), str(SECRET_PY))
    add("endpoint_extractor", ENDPOINT_PY.is_file(), str(ENDPOINT_PY))
    sec = SECRET_PY.read_text(encoding="utf-8")
    add("secret_require_output", "必须 --output" in sec, "vendor 禁写回")
    add("secret_rules", sec.count("re.compile") >= 40, "regex>=40")
    ep = ENDPOINT_PY.read_text(encoding="utf-8")
    add("ep_require_output", "必须 --output" in ep, "vendor 禁写回")
    add("wx_request", "wx.request" in ep, "wx.request")
    add("playbook", (ENGINE / PLAYBOOK).is_file(), PLAYBOOK)
    add("skill", (ENGINE / "杀招/微域/SKILL.md").is_file(), "skill")
    tmp = Path("/tmp/se-wxmini-doctor")
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir()
    (tmp / "app.json").write_text(
        json.dumps({"pages": ["pages/index/index", "pages/admin/manage"]}),
        encoding="utf-8",
    )
    (tmp / "app.js").write_text(
        "CryptoJS.AES.encrypt(x, k);\n"
        "wx.request({url:'https://api.example-not-real.test/v1/login'});\n"
        "wx.setStorageSync('token', t);\n"
        'const appsecret = "abcdef0123456789abcdef0123456789";\n',
        encoding="utf-8",
    )
    (tmp / "pay.wxml").write_text('<web-view src="{{webUrl}}"></web-view>\n', encoding="utf-8")
    out = Path("/tmp/se-wxmini-doctor-out")
    if out.exists():
        shutil.rmtree(out)
    rc = cmd_run(
        argparse.Namespace(
            dir=str(tmp),
            out=str(out),
            case="",
            probe_urls=False,
            quiet=True,
            focus="支付 amount",
        )
    )
    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    add("run-rc", rc == 0, str(rc))
    add("inventory", (out / "file_inventory.json").is_file(), "file_inventory")
    add("hidden-admin", any(x.get("page", "").find("admin") >= 0 for x in summary.get("hidden_pages") or []), "admin page")
    add("crypto", any(h["name"] == "cryptojs-aes" for h in summary.get("crypto") or []), str(summary.get("crypto")))
    add("vuln-webview", any(h["name"] == "webview-bind" for h in summary.get("vulns") or []), "web-view bind")
    add("domains-txt", (out / "domains.txt").is_file(), "domains.txt")
    add("no-write-src", not (tmp / "raw_secrets.json").exists(), "源码目录干净")
    add("phase2-secrets", (out / "secrets_report.json").is_file(), "secrets_report")
    add("phase2-api", (out / "api_endpoints.json").is_file(), "api_endpoints")
    add("phase3-report", (out / "security_report.md").is_file(), "security_report.md")
    add("phase3-full", (out / "secrets_full.md").is_file() and (out / "api_endpoints_full.md").is_file(), "full md")
    add("custom", (out / "custom_analysis.json").is_file(), "focus→custom")
    failed = [c for c in checks if not c["ok"]]
    print(f"doctor {len(checks) - len(failed)}/{len(checks)}")
    return 1 if failed else 0


def cmd_scan(args: argparse.Namespace) -> int:
    target = Path(args.dir).expanduser().resolve()
    if not target.exists():
        print(f"[!] 不存在: {target}", file=sys.stderr)
        return 2
    if args.case:
        out = ENGINE / "案卷" / args.case / "测绘" / "wxmini"
    elif args.out:
        out = Path(args.out).expanduser().resolve()
    else:
        out = target.parent / "wxaudit-output" if target.is_dir() else target.parent / "wxaudit-output"
    if target.is_file() and target.suffix.lower() == ".wxapkg":
        scan_root = out / "unpacked"
        scan_root.mkdir(parents=True, exist_ok=True)
        packs = [target]
    else:
        scan_root = target
        packs = _find_wxapkg(target)
    if out == scan_root or _is_under(out, scan_root):
        print("[!] 禁止把结果写回小程序源码目录，请 --out 或 --case", file=sys.stderr)
        return 2
    out.mkdir(parents=True, exist_ok=True)
    unveilr_rows: list[dict[str, Any]] = []
    if packs and not any(scan_root.rglob("*.js")):
        unveilr_rows = _try_unveilr(packs, out / "unpacked")
        if any(r.get("ok") for r in unveilr_rows):
            scan_root = out / "unpacked"
    inv = write_inventory(scan_root, out)
    js_n = inv.get("counts", {}).get("js_files", 0)
    if js_n == 0 and packs:
        print("[!] 目录里没有 JS，只有 wxapkg。本机装 unveilr 后再扫，或先反编译。", file=sys.stderr)
    _run_scanner(SECRET_PY, scan_root, out)
    _run_scanner(ENDPOINT_PY, scan_root, out)
    secrets = json.loads((out / "raw_secrets.json").read_text(encoding="utf-8"))
    endpoints = json.loads((out / "raw_endpoints.json").read_text(encoding="utf-8"))
    hosts = _hosts_from_endpoints(endpoints)
    fuzz = _fuzz_paths(endpoints)
    crypto = _scan_pats(scan_root, CRYPTO_PATS)
    vulns = _scan_pats(scan_root, VULN_PATS)
    hidden = _hidden_pages(scan_root)
    probed: list[dict[str, Any]] = []
    if args.probe_urls:
        probed = _probe_urls(hosts)
    crit = sum(
        1
        for h in (secrets.get("all_hits") or [])
        if str(h.get("severity") or "") == "Critical" and not h.get("is_placeholder")
    )
    strong_crypto = any(h["severity"] in {"High", "Critical"} for h in crypto)
    strong_vuln = any(h["severity"] in {"High", "Critical"} for h in vulns + hidden)
    level = "L0"
    if secrets.get("non_placeholder_hits") or endpoints.get("total_raw_hits") or crypto or vulns:
        level = "L1"
    if crit or strong_crypto or strong_vuln or any(h.get("in_scope") for h in hosts):
        level = "L2"
    if probed and any(p.get("status") == 200 for p in probed):
        level = "L2"
    (out / "domains.txt").write_text(
        "\n".join(h["host"] for h in hosts) + ("\n" if hosts else ""), encoding="utf-8"
    )
    (out / "endpoints_fuzz.txt").write_text(
        "\n".join(fuzz) + ("\n" if fuzz else ""), encoding="utf-8"
    )
    summary = {
        "ts": _now(),
        "playbook": PLAYBOOK,
        "target_dir": str(scan_root),
        "level": level,
        "wxapkg": [str(p) for p in packs],
        "unveilr": unveilr_rows,
        "inventory_counts": inv.get("counts"),
        "secrets_non_placeholder": secrets.get("non_placeholder_hits"),
        "secrets_critical": crit,
        "endpoint_hits": endpoints.get("total_raw_hits"),
        "hosts": hosts,
        "crypto": crypto,
        "vulns": vulns,
        "hidden_pages": hidden,
        "probe_urls": probed,
        "next": (
            "Critical 钥走假支付/云 AK；授权 host 才 --probe-urls；"
            "金额/IDOR 只记前端证据，回灌走对象矩阵"
        ),
    }
    (out / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    if args.case:
        write_probe_json(
            summary, case=args.case, case_subdir="wxmini", filename="probe_summary.json"
        )
    if getattr(args, "focus", ""):
        _write_custom_requests(out, str(args.focus))
    if not getattr(args, "quiet", False):
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


PHASE2_FILES = (
    "secrets_report.json",
    "api_endpoints.json",
    "crypto_analysis.json",
    "vuln_analysis.json",
)


def _out_dir(args: argparse.Namespace) -> Path:
    if getattr(args, "case", None):
        return ENGINE / "案卷" / args.case / "测绘" / "wxmini"
    if getattr(args, "out", None):
        return Path(args.out).expanduser().resolve()
    d = getattr(args, "dir", None)
    if d:
        t = Path(d).expanduser().resolve()
        return t.parent / "wxaudit-output"
    raise SystemExit("[!] analyze/report 必须 --out 或 --case（或带 --dir 用默认 wxaudit-output）")


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _require(out: Path, names: list[str], hint: str) -> int:
    missing = [n for n in names if not (out / n).is_file() or (out / n).stat().st_size == 0]
    if missing:
        print(f"[!] {hint} 缺: {', '.join(missing)}", file=sys.stderr)
        return 2
    return 0


def _write_custom_requests(out: Path, focus: str) -> dict[str, Any]:
    tokens = [t for t in re.findall(r"[A-Za-z0-9_./-]{2,}|[\u4e00-\u9fff]{2,}", focus) if t]
    data = {
        "has_custom_requests": bool(tokens),
        "focus": focus,
        "targets": [{"type": "focus_area", "value": t, "context": focus} for t in tokens[:20]],
    }
    _write_json(out / "custom_requests.json", data)
    return data


def _sev_rank(s: str) -> int:
    return {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}.get(s, 5)


def _analyze_secrets(raw: dict[str, Any]) -> dict[str, Any]:
    findings = []
    for h in raw.get("all_hits") or []:
        if h.get("is_placeholder"):
            continue
        findings.append(
            {
                "category": h.get("category"),
                "sub_type": h.get("sub_type"),
                "severity": h.get("severity") or "Info",
                "value": str(h.get("value") or "")[:240],
                "file": h.get("file"),
                "line": h.get("line"),
                "context": str(h.get("context") or "")[:200],
            }
        )
    findings.sort(key=lambda x: (_sev_rank(str(x["severity"])), str(x.get("category"))))
    by_sev: dict[str, int] = defaultdict(int)
    for f in findings:
        by_sev[str(f["severity"])] += 1
    return {
        "ts": _now(),
        "source": "raw_secrets.json",
        "placeholder_dropped": int(raw.get("total_raw_hits") or 0) - len(findings),
        "severity_statistics": dict(by_sev),
        "findings": findings,
        "count": len(findings),
    }


def _analyze_endpoints(raw: dict[str, Any]) -> dict[str, Any]:
    bases = []
    for bu in raw.get("base_url_candidates") or []:
        v = str(bu.get("value") or "").rstrip("/")
        if v.startswith("http"):
            bases.append(v)
    bases = list(dict.fromkeys(bases))
    endpoints: list[dict[str, Any]] = []
    seen: set[str] = set()
    for h in raw.get("all_hits") or []:
        val = str(h.get("value") or "").strip()
        if not val or val in {"request", "http", "api"}:
            continue
        full = val
        if val.startswith("/") and bases:
            full = bases[0] + val
        elif val.startswith("//"):
            full = "https:" + val
        key = full
        if key in seen:
            continue
        seen.add(key)
        host = host_of(full) if "://" in full else ""
        in_sc = False
        skip = ""
        if host:
            low = host.lower()
            if any(low == s or low.endswith("." + s) for s in SKIP_HOST_SUFFIX):
                skip = "wechat-cdn"
            else:
                try:
                    in_sc = bool(in_scope(host) or in_scope("https://" + host))
                except Exception:
                    in_sc = False
        endpoints.append(
            {
                "url": full[:300],
                "raw": val[:200],
                "type": h.get("type"),
                "file": h.get("file"),
                "line": h.get("line"),
                "host": host,
                "in_scope": in_sc,
                "skip_reason": skip,
            }
        )
    return {
        "ts": _now(),
        "source": "raw_endpoints.json",
        "base_urls": bases,
        "count": len(endpoints),
        "endpoints": endpoints,
    }


def _analyze_crypto(summary: dict[str, Any]) -> dict[str, Any]:
    items = list(summary.get("crypto") or [])
    return {
        "ts": _now(),
        "count": len(items),
        "schemes": items,
        "note": "机器面；算法还原走 js-reverse，禁止在小程序里盲 decrypt",
    }


def _analyze_vulns(summary: dict[str, Any]) -> dict[str, Any]:
    vulns = []
    for h in summary.get("vulns") or []:
        vulns.append(
            {
                "id": h.get("name"),
                "dim": h.get("dim"),
                "severity": h.get("severity"),
                "file": h.get("file"),
                "line": h.get("line"),
                "evidence": h.get("snippet"),
                "confirm": "需后端验证" if h.get("dim") in {"biz", "auth"} else "前端已确认",
            }
        )
    for p in summary.get("hidden_pages") or []:
        vulns.append(
            {
                "id": "hidden-page",
                "dim": "config",
                "severity": p.get("severity") or "High",
                "file": p.get("file"),
                "line": 0,
                "evidence": p.get("page"),
                "confirm": "前端已确认",
            }
        )
    vulns.sort(key=lambda x: _sev_rank(str(x.get("severity"))))
    return {"ts": _now(), "count": len(vulns), "vulnerabilities": vulns}


def _analyze_custom(out: Path, secrets: dict[str, Any], apis: dict[str, Any], vulns: dict[str, Any]) -> dict[str, Any] | None:
    req_p = out / "custom_requests.json"
    if not req_p.is_file():
        return None
    req = _read_json(req_p)
    if not req.get("has_custom_requests"):
        return None
    tokens = [str(t.get("value") or "").lower() for t in req.get("targets") or [] if t.get("value")]
    tokens = [t for t in tokens if len(t) >= 2]

    def hit(blob: str) -> bool:
        low = blob.lower()
        return any(t in low for t in tokens)

    matched_sec = [f for f in secrets.get("findings") or [] if hit(json.dumps(f, ensure_ascii=False))]
    matched_api = [e for e in apis.get("endpoints") or [] if hit(json.dumps(e, ensure_ascii=False))]
    matched_v = [v for v in vulns.get("vulnerabilities") or [] if hit(json.dumps(v, ensure_ascii=False))]
    data = {
        "ts": _now(),
        "focus": req.get("focus"),
        "tokens": tokens,
        "secrets": matched_sec[:50],
        "endpoints": matched_api[:80],
        "vulnerabilities": matched_v[:40],
        "note": "按 --focus 关键词从 Phase 2 结果里抽；深度数据流仍由主会话补一句",
    }
    _write_json(out / "custom_analysis.json", data)
    return data


def cmd_analyze(args: argparse.Namespace) -> int:
    out = _out_dir(args)
    if _require(out, ["file_inventory.json", "raw_secrets.json", "raw_endpoints.json", "summary.json"], "先 scan"):
        return 2
    raw_s = _read_json(out / "raw_secrets.json")
    raw_e = _read_json(out / "raw_endpoints.json")
    summary = _read_json(out / "summary.json")
    secrets = _analyze_secrets(raw_s)
    apis = _analyze_endpoints(raw_e)
    crypto = _analyze_crypto(summary)
    vulns = _analyze_vulns(summary)
    _write_json(out / "secrets_report.json", secrets)
    _write_json(out / "api_endpoints.json", apis)
    _write_json(out / "crypto_analysis.json", crypto)
    _write_json(out / "vuln_analysis.json", vulns)
    custom = _analyze_custom(out, secrets, apis, vulns)
    if getattr(args, "focus", "") and not (out / "custom_requests.json").is_file():
        _write_custom_requests(out, str(args.focus))
        custom = _analyze_custom(out, secrets, apis, vulns)
    payload = {
        "ts": _now(),
        "secrets": secrets["count"],
        "endpoints": apis["count"],
        "crypto": crypto["count"],
        "vulns": vulns["count"],
        "custom": bool(custom),
    }
    _write_json(out / "phase2.json", payload)
    if not getattr(args, "quiet", False):
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def _md_escape(s: Any) -> str:
    return str(s or "").replace("|", "\\|").replace("\n", " ")[:200]


def cmd_report(args: argparse.Namespace) -> int:
    out = _out_dir(args)
    if _require(out, ["file_inventory.json"], "先 scan"):
        return 2
    present = [n for n in PHASE2_FILES if (out / n).is_file()]
    if len(present) < 3:
        print(f"[!] Phase 2 不足（{len(present)}/4）：先 analyze。已有 {present}", file=sys.stderr)
        return 2
    inv = _read_json(out / "file_inventory.json")
    summary = _read_json(out / "summary.json") if (out / "summary.json").is_file() else {}
    secrets = _read_json(out / "secrets_report.json") if (out / "secrets_report.json").is_file() else {"findings": [], "count": 0}
    apis = _read_json(out / "api_endpoints.json") if (out / "api_endpoints.json").is_file() else {"endpoints": [], "count": 0}
    crypto = _read_json(out / "crypto_analysis.json") if (out / "crypto_analysis.json").is_file() else {"schemes": [], "count": 0}
    vulns = _read_json(out / "vuln_analysis.json") if (out / "vuln_analysis.json").is_file() else {"vulnerabilities": [], "count": 0}
    custom = _read_json(out / "custom_analysis.json") if (out / "custom_analysis.json").is_file() else None
    req = _read_json(out / "custom_requests.json") if (out / "custom_requests.json").is_file() else {}
    counts = inv.get("counts") or {}
    crit_sec = [f for f in secrets.get("findings") or [] if f.get("severity") in {"Critical", "High"}]
    hot_api = [e for e in apis.get("endpoints") or [] if e.get("in_scope") or "/pay" in str(e.get("url") or "").lower() or "/order" in str(e.get("url") or "").lower()]
    appids = [
        f.get("value")
        for f in secrets.get("findings") or []
        if f.get("sub_type") == "appid"
    ][:3]
    lines = [
        "# 微信小程序安全审计报告",
        "",
        "## 基本信息",
        "",
        "| 项 | 值 |",
        "|----|----|",
        f"| 时间 | {summary.get('ts') or _now()} |",
        f"| 档位 | {summary.get('level') or '-'} |",
        f"| AppID | {_md_escape(', '.join(str(x) for x in appids) or '-')} |",
        f"| JS | {counts.get('js_files', 0)} |",
        f"| JSON | {counts.get('json_files', 0)} |",
        f"| WXML | {counts.get('wxml_files', 0)} |",
        f"| 密钥(非占位) | {secrets.get('count', 0)} |",
        f"| 接口 | {apis.get('count', 0)} |",
        f"| 加解密命中 | {crypto.get('count', 0)} |",
        f"| 漏洞面 | {vulns.get('count', 0)} |",
        "",
        "## 执行摘要",
        "",
        f"- Critical/High 密钥 {len(crit_sec)} 条；授权域接口 {sum(1 for e in apis.get('endpoints') or [] if e.get('in_scope'))} 条。",
        "- 金额/IDOR 只记前端证据，需后端验证，本报告不生成 PoC。",
        "",
        "## 高危密钥",
        "",
    ]
    if not crit_sec:
        lines.append("无 Critical/High 非占位符密钥。")
    else:
        lines += ["| 级别 | 类 | 值 | 文件:行 |", "|------|----|----|---------|"]
        for f in crit_sec[:40]:
            lines.append(
                f"| {f.get('severity')} | {f.get('category')}/{f.get('sub_type')} | `{_md_escape(f.get('value'))}` | {_md_escape(f.get('file'))}:{f.get('line')} |"
            )
    lines += ["", "## 关键接口", "", "| URL | scope | 文件 |", "|-----|-------|------|"]
    show = hot_api[:30] or (apis.get("endpoints") or [])[:20]
    if not show:
        lines.append("| - | - | 无 |")
    else:
        for e in show:
            sc = "in" if e.get("in_scope") else (e.get("skip_reason") or "out")
            lines.append(f"| `{_md_escape(e.get('url'))}` | {sc} | {_md_escape(e.get('file'))} |")
    lines += ["", "完整列表见 `api_endpoints_full.md`。", "", "## 加解密", ""]
    if not crypto.get("schemes"):
        lines.append("未命中常见库。")
    else:
        lines += ["| 名称 | 级别 | 文件:行 |", "|------|------|---------|"]
        for c in crypto.get("schemes") or []:
            lines.append(f"| {c.get('name')} | {c.get('severity')} | {_md_escape(c.get('file'))}:{c.get('line')} |")
    lines += ["", "## 漏洞面（七维机器结果）", ""]
    if not vulns.get("vulnerabilities"):
        lines.append("无正则命中。")
    else:
        lines += ["| 级别 | 维 | id | 证实 | 证据 |", "|------|----|----|------|------|"]
        for v in vulns.get("vulnerabilities") or []:
            lines.append(
                f"| {v.get('severity')} | {v.get('dim')} | {v.get('id')} | {v.get('confirm')} | `{_md_escape(v.get('evidence'))}` |"
            )
    if req.get("has_custom_requests"):
        lines += ["", "## 定向分析（--focus）", ""]
        if not custom:
            lines.append("⚠️ 有 custom_requests 但没有 custom_analysis.json，Phase 2.5 未跑完。")
        else:
            lines.append(f"关注：`{_md_escape(custom.get('focus'))}`")
            lines.append(f"- 命中密钥 {len(custom.get('secrets') or [])} / 接口 {len(custom.get('endpoints') or [])} / 漏洞 {len(custom.get('vulnerabilities') or [])}")
    lines += [
        "",
        "## 审计完整性",
        "",
        f"- Phase 2 文件：{', '.join(present)}（{len(present)}/4）",
        f"- custom：{'有' if custom else ('声明了但未分析' if req.get('has_custom_requests') else '无')}",
        "- 全量密钥 → `secrets_full.md`；全量接口 → `api_endpoints_full.md`",
        "",
        "## 下一刀",
        "",
        "- 支付钥 → 假支付；云 AK → 阿里云 AK 卡",
        "- 授权 host 才 `--probe-urls`；越权走对象矩阵",
        "- `<web-view src={{` → `webview-deeplink-bridge`",
        "",
    ]
    (out / "security_report.md").write_text("\n".join(lines), encoding="utf-8")
    sec_full = ["# 全量敏感信息", "", "| 级别 | 类 | 值 | 文件:行 |", "|------|----|----|---------|"]
    for f in secrets.get("findings") or []:
        sec_full.append(
            f"| {f.get('severity')} | {f.get('category')}/{f.get('sub_type')} | `{_md_escape(f.get('value'))}` | {_md_escape(f.get('file'))}:{f.get('line')} |"
        )
    (out / "secrets_full.md").write_text("\n".join(sec_full) + "\n", encoding="utf-8")
    api_full = ["# 全量接口", "", "| URL | scope | 文件:行 |", "|-----|-------|---------|"]
    for e in apis.get("endpoints") or []:
        sc = "in" if e.get("in_scope") else (e.get("skip_reason") or "out")
        api_full.append(f"| `{_md_escape(e.get('url'))}` | {sc} | {_md_escape(e.get('file'))}:{e.get('line')} |")
    (out / "api_endpoints_full.md").write_text("\n".join(api_full) + "\n", encoding="utf-8")
    findings = {
        "ts": _now(),
        "level": summary.get("level"),
        "secrets": secrets.get("count"),
        "endpoints": apis.get("count"),
        "crypto": crypto.get("count"),
        "vulns": vulns.get("count"),
        "report": "security_report.md",
        "qc": {
            "secrets_full_rows": max(0, len(sec_full) - 4),
            "secrets_findings": secrets.get("count", 0),
            "api_full_rows": max(0, len(api_full) - 4),
            "api_count": apis.get("count", 0),
            "vuln_rows": len(vulns.get("vulnerabilities") or []),
        },
    }
    qc = findings["qc"]
    if qc["secrets_full_rows"] < qc["secrets_findings"] or qc["api_full_rows"] < qc["api_count"]:
        print("[!] QC：全量 md 行数少于 JSON，报告不完整", file=sys.stderr)
        return 2
    _write_json(out / "findings.json", findings)
    if args.case:
        write_probe_json(findings, case=args.case, case_subdir="wxmini", filename="findings.json")
    if not getattr(args, "quiet", False):
        print(json.dumps(findings, ensure_ascii=False, indent=2))
        print(f"[+] 报告: {out / 'security_report.md'}")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    rc = cmd_scan(args)
    if rc:
        return rc
    rc = cmd_analyze(args)
    if rc:
        return rc
    return cmd_report(args)


def main() -> int:
    ap = argparse.ArgumentParser(description="微信小程序静态审计")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("doctor")

    def add_io(p: argparse.ArgumentParser, need_dir: bool) -> None:
        if need_dir:
            p.add_argument("--dir", required=True, help="反编译目录或单个 .wxapkg")
        p.add_argument("--out", help="输出目录（禁止等于 --dir）")
        p.add_argument("--case", help="案卷名")
        p.add_argument("--focus", default="", help="用户关注点，写入 custom_requests（如 支付 amount）")
        p.add_argument("--probe-urls", action="store_true", help="对 in_scope host 做 GET（先问）")
        p.add_argument("--quiet", action="store_true")

    add_io(sub.add_parser("scan", help="Phase 1+1.5"), True)
    add_io(sub.add_parser("analyze", help="Phase 2 四份 JSON"), False)
    add_io(sub.add_parser("report", help="Phase 3 报告"), False)
    add_io(sub.add_parser("run", help="scan+analyze+report（默认入口）"), True)
    args = ap.parse_args()
    if args.cmd == "doctor":
        return cmd_doctor()
    if args.cmd == "scan":
        return cmd_scan(args)
    if args.cmd == "analyze":
        return cmd_analyze(args)
    if args.cmd == "report":
        return cmd_report(args)
    if args.cmd == "run":
        return cmd_run(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
