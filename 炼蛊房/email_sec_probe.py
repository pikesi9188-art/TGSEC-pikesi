#!/usr/bin/env python3
"""授权飞书 / 醒教面：SPF·DMARC 认形 + eml 头 + 诱饵页表单。不搭发信基础设施。

  python3 炼蛊房/email_sec_probe.py list
  python3 炼蛊房/email_sec_probe.py dns --domain <授权域> --case <案>
  python3 炼蛊房/email_sec_probe.py eml --path 信.eml --case <案>
  python3 炼蛊房/email_sec_probe.py lure --path 页.html --case <案>
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import host_of, in_scope, write_probe_json  # noqa: E402


def _txt(name: str) -> list[str]:
    try:
        import dns.resolver  # type: ignore
        ans = dns.resolver.resolve(name, "TXT")
        return [b"".join(r.strings).decode("utf-8", "replace") for r in ans]
    except Exception:
        pass
    import subprocess
    try:
        out = subprocess.check_output(["dig", "+short", "TXT", name], text=True, timeout=8)
    except (OSError, subprocess.SubprocessError):
        return []
    return [ln.strip().strip('"') for ln in out.splitlines() if ln.strip()]


def dns_audit(domain: str) -> dict:
    spf = [t for t in _txt(domain) if "v=spf1" in t.lower()]
    dmarc = _txt(f"_dmarc.{domain}")
    dkim_hits = []
    for sel in ("default", "google", "k1", "selector1", "s1"):
        recs = _txt(f"{sel}._domainkey.{domain}")
        if any("v=DKIM1" in t.upper() or "p=" in t for t in recs):
            dkim_hits.append(sel)
    dmarc_txt = " ".join(dmarc).lower()
    policy = ""
    m = re.search(r"\bp=([a-z]+)", dmarc_txt)
    if m:
        policy = m.group(1)
    weak = (not spf) or any("~all" in t or "?all" in t for t in spf) or policy in {"", "none"}
    return {
        "spf": spf[:3],
        "dmarc": dmarc[:2],
        "dmarc_p": policy or "missing",
        "dkim_selectors": dkim_hits,
        "weak": weak,
    }


def parse_eml(text: str) -> dict:
    head = text.split("\n\n", 1)[0] if "\n\n" in text else text[:4000]
    fields = {}
    for key in ("From", "To", "Subject", "Return-Path", "Reply-To", "Authentication-Results"):
        m = re.search(rf"(?im)^{key}:\s*(.+)$", head)
        if m:
            fields[key.lower()] = m.group(1).strip()[:200]
    auth = fields.get("authentication-results", "").lower()
    return {
        "fields": fields,
        "spf_fail": "spf=fail" in auth,
        "dmarc_fail": "dmarc=fail" in auth,
        "lookalike": bool(re.search(r"rn|vv|0o|1l", fields.get("from", "").lower())),
    }


def parse_lure(html: str) -> dict:
    low = html.lower()
    return {
        "password_field": "type=\"password\"" in low or "type='password'" in low,
        "email_field": "type=\"email\"" in low or "name=\"email\"" in low,
        "action": (re.search(r'<form[^>]+action=["\']([^"\']+)', low) or [None, ""])[1][:160],
        "js_submit": "onsubmit" in low,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="授权邮件 / 醒教面")
    ap.add_argument("cmd", choices=("list", "dns", "eml", "lure"))
    ap.add_argument("--domain", default="")
    ap.add_argument("--path", default="")
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    if args.cmd == "list":
        print(json.dumps({"cmds": ["dns", "eml", "lure"]}, ensure_ascii=False, indent=2))
        return 0
    if args.cmd == "dns":
        host = host_of(args.domain) or args.domain
        if not host or not in_scope(host):
            print(f"[!] 不在 scope：{host or args.domain}", file=sys.stderr)
            return 2
        info = dns_audit(host)
        level = "L2" if info["weak"] or info["dkim_selectors"] or info["spf"] else "none"
        rec = {"skill": "email-security", "domain": host, **info, "level": level, "ts": datetime.now(UTC).isoformat()}
        out = write_probe_json(rec, case=args.case, out=args.out, case_subdir="email", filename="dns.json")
        print(json.dumps({"level": level, "dmarc_p": info["dmarc_p"], "weak": info["weak"], "out": str(out)}, ensure_ascii=False))
        return 0
    p = Path(args.path)
    if not p.is_file():
        print("[!] --path 不存在", file=sys.stderr)
        return 2
    text = p.read_text(encoding="utf-8", errors="replace")
    if args.cmd == "eml":
        info = parse_eml(text)
        level = "L2" if info["fields"] else "none"
        skill = "email-security"
        sub = "eml.json"
    else:
        info = parse_lure(text)
        level = "L2" if info["password_field"] else ("L1" if info["email_field"] else "none")
        skill = "security-awareness-training"
        sub = "lure.json"
    rec = {"skill": skill, "path": str(p), **info, "level": level, "ts": datetime.now(UTC).isoformat()}
    out = write_probe_json(rec, case=args.case, out=args.out, case_subdir="email", filename=sub)
    print(json.dumps({"level": level, "out": str(out)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
