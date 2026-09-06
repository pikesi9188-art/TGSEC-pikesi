#!/usr/bin/env python3
"""源站 / 旁路自动化：FOFA + cdn_tracer + 轻量历史 DNS → 案卷/origin.json，并回写 Triage。

示例:
  python3 炼蛊房/origin_recon.py \\
    --domain 授权站 --case <案卷> --no-verify
"""
from __future__ import annotations

import argparse
import json
import re
import socket
import subprocess
import sys
import urllib.request
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

_OPS = Path(__file__).resolve().parent
ENGINE = (_OPS.parent if (_OPS.parent / "杀招").is_dir() else (_OPS.parent if (_OPS.parent / "杀招").is_dir() else _OPS.parents[1]))
CDN_TRACER = ENGINE / "tools" / "vendor" / "01-recon" / "cdn-origin-tracing" / "cdn_tracer.py"
if str(_OPS) not in sys.path:
    sys.path.insert(0, str(_OPS))

from scope_lib import host_of, in_scope, is_denied  # noqa: E402
import ssl



def _ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _case_dir(case: str) -> Path:
    return ENGINE / "案卷" / case


def run_cdn_tracer(domain: str, out_json: Path, *, no_verify: bool, threads: int) -> dict:
    if not CDN_TRACER.is_file():
        return {"error": f"missing {CDN_TRACER}"}
    cmd = [
        sys.executable,
        str(CDN_TRACER),
        domain,
        "-o",
        str(out_json),
        "--threads",
        str(threads),
    ]
    if no_verify:
        cmd.append("--no-verify")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300, cwd=str(CDN_TRACER.parent))
        data = {}
        if out_json.is_file():
            data = json.loads(out_json.read_text(encoding="utf-8"))
        data["_exit"] = r.returncode
        data["_stderr_tail"] = (r.stderr or "")[-500:]
        return data
    except Exception as e:
        return {"error": str(e)}


def run_fofa(domain: str, size: int = 50) -> dict[str, Any]:
    """用引擎 FofaClient；无 key 则跳过。"""
    out: dict[str, Any] = {"queries": [], "assets": [], "skipped": False}
    try:
        import yaml

        cfg_path = ENGINE / "config.yaml"
        if not cfg_path.is_file():
            out["skipped"] = True
            out["reason"] = "no config.yaml"
            return out
        cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
        fcfg = cfg.get("fofa") or {}
        key = fcfg.get("key") or ""
        email = fcfg.get("email") or ""
        if not key:
            out["skipped"] = True
            out["reason"] = "no fofa.key"
            return out
        sys.path.insert(0, str(ENGINE))
        from engine.collectors import FofaClient

        client = FofaClient(email, key) if email else FofaClient(key)
        queries = [
            f'domain="{domain}"',
            f'host="{domain}"',
            f'cert="{domain}"',
        ]
        seen = set()
        for q in queries:
            out["queries"].append(q)
            try:
                assets = client.search(q, size=size)
            except Exception as e:
                out.setdefault("errors", []).append({q: str(e)})
                continue
            for a in assets:
                ip = getattr(a, "ip", "") or ""
                port = getattr(a, "port", 0) or 0
                key2 = f"{ip}:{port}"
                if key2 in seen:
                    continue
                seen.add(key2)
                out["assets"].append(
                    {
                        "ip": ip,
                        "port": port,
                        "host": getattr(a, "host", "") or "",
                        "service": getattr(a, "service", "") or "",
                        "banner": (getattr(a, "banner", "") or "")[:200],
                        "query": q,
                    }
                )
    except Exception as e:
        out["skipped"] = True
        out["reason"] = str(e)
    return out


def crt_sh_lookup(domain: str) -> dict[str, Any]:
    """crt.sh 证书透明度 → 发现同一证书覆盖的 IP / 主机名。
    常见命中：CF 接入前的裸 IP、内网域名、原始 VPS 主机名。"""
    result: dict[str, Any] = {"ips": [], "domains": [], "certs": [], "source": "crt.sh"}
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "大爱仙尊-origin_recon"})
        with urllib.request.urlopen(req, timeout=15, context=_ssl_ctx()) as resp:
            certs = json.loads(resp.read().decode("utf-8", "replace"))
        seen_names = set()
        for c in (certs or [])[:500]:
            names_raw = c.get("name_value") or ""
            for name in names_raw.replace("\\n", "\n").splitlines():
                name = name.strip().lstrip("*.")
                if not name or name in seen_names:
                    continue
                seen_names.add(name)
                # 若是 IP 直接收录
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", name):
                    if name not in result["ips"]:
                        result["ips"].append(name)
                elif name.endswith(f".{domain}") or name == domain:
                    pass  # 主域子域跳过
                else:
                    # 旁域：可能是同一证书覆盖的其他站，或 IP-based SAN
                    result["domains"].append(name)
        result["total_certs"] = len(certs or [])
    except Exception as exc:
        result["error"] = str(exc)
    return result


def spf_mx_lookup(domain: str) -> dict[str, Any]:
    """SPF / MX / DMARC 记录 → 发件服务器 IP，往往和 Web 同机房。"""
    result: dict[str, Any] = {"ips": [], "mx_hosts": [], "spf_raw": "", "sources": []}
    try:
        import subprocess as _sp
        for rtype, target in (("TXT", domain), ("MX", domain), ("TXT", f"_dmarc.{domain}")):
            try:
                r = _sp.run(["dig", "+short", rtype, target],
                            capture_output=True, text=True, timeout=10)
                if r.returncode == 0 and r.stdout.strip():
                    result["sources"].append(f"{rtype}/{target}")
                    for line in r.stdout.splitlines():
                        line = line.strip().strip('"')
                        if rtype == "TXT" and "v=spf1" in line.lower():
                            result["spf_raw"] = line
                            # 解析 ip4: / include: 里的 IP
                            for m in re.finditer(r"ip4:([\d./]+)", line):
                                ip = m.group(1).split("/")[0]
                                if ip not in result["ips"]:
                                    result["ips"].append(ip)
                        elif rtype == "MX":
                            # MX 记录：优先级 主机名
                            parts = line.split()
                            if len(parts) >= 2:
                                mx_host = parts[-1].rstrip(".")
                                result["mx_hosts"].append(mx_host)
                                # 解析 MX 主机 IP
                                try:
                                    for info in socket.getaddrinfo(mx_host, None):
                                        ip = info[4][0]
                                        if ip not in result["ips"]:
                                            result["ips"].append(ip)
                                except Exception:
                                    pass
            except Exception:
                continue
    except Exception as exc:
        result["error"] = str(exc)
    return result


def securitytrails_passive_dns(domain: str, api_key: str = "") -> dict[str, Any]:
    """SecurityTrails 历史 DNS（需 API key；无 key 则跳过）。
    免费套餐：50 次/月，命中率极高（CF 接入前的裸 A 记录）。"""
    result: dict[str, Any] = {"historical_a": [], "skipped": not api_key}
    if not api_key:
        result["reason"] = "no api_key; set SECURITYTRAILS_KEY env or pass --st-key"
        return result
    try:
        url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
        req = urllib.request.Request(
            url,
            headers={"apikey": api_key, "User-Agent": "大爱仙尊-origin_recon"},
        )
        with urllib.request.urlopen(req, timeout=15, context=_ssl_ctx()) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        for rec in (data.get("records") or []):
            for v in (rec.get("values") or []):
                ip = v.get("ip") or ""
                if ip and ip not in result["historical_a"]:
                    result["historical_a"].append(ip)
        result["total_records"] = data.get("record_count", 0)
    except Exception as exc:
        result["error"] = str(exc)
    return result


def hist_dns(domain: str) -> dict[str, Any]:
    """轻量历史/旁路：HackerTarget + 本机 dig/host。"""
    result: dict[str, Any] = {"a": [], "passive": [], "sources": []}
    try:
        infos = socket.getaddrinfo(domain, None)
        for info in infos:
            ip = info[4][0]
            if ip not in result["a"]:
                result["a"].append(ip)
        result["sources"].append("socket.getaddrinfo")
    except Exception as e:
        result["resolve_error"] = str(e)

    # dig
    for cmd in (["dig", "+short", "A", domain], ["host", "-t", "A", domain]):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if r.returncode == 0 and r.stdout.strip():
                result["sources"].append(cmd[0])
                for line in r.stdout.splitlines():
                    m = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
                    for ip in m:
                        if ip not in result["a"]:
                            result["a"].append(ip)
                break
        except Exception:
            continue

    # HackerTarget hostsearch / dnslookup（公开、限速）
    for url in (
        f"https://api.hackertarget.com/hostsearch/?q={domain}",
        f"https://api.hackertarget.com/dnslookup/?q={domain}",
    ):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "大爱仙尊-origin_recon"})
            with urllib.request.urlopen(req, timeout=12, context=_ssl_ctx()) as resp:
                text = resp.read().decode("utf-8", "replace")
            if "error" in text.lower() and len(text) < 80:
                continue
            result["sources"].append(url.split("/")[3])
            for line in text.splitlines()[:200]:
                ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
                for ip in ips:
                    result["passive"].append({"ip": ip, "line": line[:120]})
                    if ip not in result["a"]:
                        result["a"].append(ip)
        except Exception as e:
            result.setdefault("ht_errors", []).append(str(e))
    return result


def extract_candidates(cdn: dict, fofa: dict, dns: dict, **kwargs) -> list[dict]:
    cands: dict[str, dict] = {}

    def add(ip: str, source: str, meta: dict | None = None):
        if not ip or is_denied(ip):
            return
        # 粗滤 Cloudflare 常见段
        if ip.startswith("104.16.") or ip.startswith("104.17.") or ip.startswith("172.67.") or ip.startswith("162.159."):
            # 仍记录但标记 cdn_likely
            pass
        e = cands.setdefault(ip, {"ip": ip, "sources": [], "cdn_likely": False, "meta": {}})
        if source not in e["sources"]:
            e["sources"].append(source)
        if meta:
            e["meta"].update(meta)
        if ip.startswith(("104.16.", "104.17.", "172.67.", "162.159.", "188.114.")):
            e["cdn_likely"] = True

    # cdn_tracer ranked
    for key in ("ranked", "candidates", "stage10_ranking", "results"):
        block = cdn.get(key)
        if isinstance(block, list):
            for item in block:
                if isinstance(item, dict):
                    ip = item.get("ip") or item.get("address") or ""
                    add(ip, "cdn_tracer", {"score": item.get("score") or item.get("confidence")})
                elif isinstance(item, str):
                    add(item, "cdn_tracer")
    # nested stage reports
    for stage_key, stage in (cdn or {}).items():
        if not isinstance(stage, dict):
            continue
        for ip in stage.get("candidate_ips") or stage.get("non_cdn_ips") or []:
            add(str(ip), f"cdn_tracer:{stage_key}")

    for a in fofa.get("assets") or []:
        add(a.get("ip") or "", "fofa", {"port": a.get("port"), "host": a.get("host")})

    for ip in dns.get("a") or []:
        add(ip, "dns")
    for p in dns.get("passive") or []:
        add(p.get("ip") or "", "passive_dns")

    # 接入 crt.sh / SPF/MX / SecurityTrails
    extra = kwargs.get("extra") or {}
    for ip in extra.get("crt_ips") or []:
        add(ip, "crt.sh")
    for ip in extra.get("spf_ips") or []:
        add(ip, "spf_mx")
    for ip in extra.get("st_ips") or []:
        add(ip, "securitytrails")

    # 优先非 CDN，多来源优先
    ranked = sorted(
        cands.values(),
        key=lambda x: (1 if x.get("cdn_likely") else 0, -len(x.get("sources") or []), x["ip"]),
    )
    return ranked


def writeback_triage(case: str, origin: dict) -> None:
    """勾选 TRIAGE / triage.json 中与源站相关的复工条件。"""
    d = _case_dir(case)
    non_cdn = [c for c in origin.get("candidates") or [] if not c.get("cdn_likely")]
    hit = len(non_cdn) > 0
    phrase_ok = "FOFA/cdn_tracer/历史DNS 出现非 CF 源站 IP"  # 模板常用语片段

    tj = d / "triage.json"
    if tj.is_file():
        try:
            meta = json.loads(tj.read_text(encoding="utf-8"))
        except Exception:
            meta = {}
        resume = list(meta.get("resume") or [])
        done = list(meta.get("resume_done") or [])
        if hit:
            for r in resume:
                if any(k in r for k in ("源站", "FOFA", "cdn_tracer", "非 CF", "origin")):
                    if r not in done:
                        done.append(r)
            # 若没有对应条目，追加一条已完成说明
            note = f"origin_recon 发现 {len(non_cdn)} 个非CDN候选"
            if note not in done:
                done.append(note)
        meta["resume_done"] = done
        meta["origin"] = {
            "updated_at": origin.get("generated_at"),
            "non_cdn_count": len(non_cdn),
            "top": [c["ip"] for c in non_cdn[:5]],
        }
        tj.write_text(json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    triage = d / "TRIAGE.md"
    if triage.is_file() and hit:
        text = triage.read_text(encoding="utf-8")
        # 把含关键词的 - [ ] 打成 - [x]
        def repl(m):
            line = m.group(0)
            body = m.group(1)
            if any(k in body for k in ("源站", "FOFA", "cdn_tracer", "非 CF", "origin", "历史 DNS", "历史DNS")):
                return f"- [x] {body}"
            return line

        text2 = re.sub(r"^- \[ \] (.+)$", repl, text, flags=re.M)
        if text2 != text:
            triage.write_text(text2, encoding="utf-8")

    status = d / f"STATUS_{case}.md"
    if not status.exists():
        status = d / "STATUS.md"
    if status.exists():
        block = (
            f"\n## Origin recon\n\n"
            f"- 时间: {origin.get('generated_at')}\n"
            f"- 非CDN候选: {len(non_cdn)} → `{', '.join(c['ip'] for c in non_cdn[:8]) or '无'}`\n"
            f"- 详表: `案卷/origin.json`\n"
        )
        st = status.read_text(encoding="utf-8")
        if "## Origin recon" in st:
            st = re.sub(
                r"## Origin recon\n(?:.*\n)*?(?=^## |\Z)",
                block.lstrip() + "\n",
                st,
                count=1,
                flags=re.M,
            )
        else:
            st = st.rstrip() + "\n" + block
        try:
            from case_triage import ensure_status_layout  # type: ignore

            status = ensure_status_layout(case)
        except Exception:
            pass
        status.write_text(st, encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description="源站/旁路自动化")
    ap.add_argument("--domain", required=True)
    ap.add_argument("--case", required=True)
    ap.add_argument("--no-verify", action="store_true", default=True)
    ap.add_argument("--verify", action="store_true", help="cdn_tracer 直连验证（更吵）")
    ap.add_argument("--threads", type=int, default=20)
    ap.add_argument("--fofa-size", type=int, default=30)
    ap.add_argument("--skip-fofa", action="store_true")
    ap.add_argument("--skip-cdn", action="store_true")
    ap.add_argument("--skip-scope-check", action="store_true")
    ap.add_argument(
        "--with-space-search",
        action="store_true",
        help="追加 Censys/ZoomEye/Quake/Shodan 证书溯源（tools/space-search）",
    )
    ap.add_argument("--with-crt", action="store_true", default=True,
                    help="crt.sh 证书透明度溯源（默认开启）")
    ap.add_argument("--skip-crt", action="store_true", help="跳过 crt.sh")
    ap.add_argument("--with-spf", action="store_true", default=True,
                    help="SPF/MX 记录溯源（默认开启）")
    ap.add_argument("--skip-spf", action="store_true", help="跳过 SPF/MX")
    ap.add_argument("--st-key", default="", help="SecurityTrails API key（可选，免费50次/月）")
    args = ap.parse_args()

    domain = host_of(args.domain)
    if not args.skip_scope_check and not in_scope(domain):
        print(f"[!] {domain} 不在 scope", file=sys.stderr)
        return 1

    recon = _case_dir(args.case) / "测绘"
    recon.mkdir(parents=True, exist_ok=True)
    cdn_out = recon / "cdn_tracer_origin.json"

    no_verify = not args.verify
    cdn = {} if args.skip_cdn else run_cdn_tracer(domain, cdn_out, no_verify=no_verify, threads=args.threads)
    print(f"[*] cdn_tracer done err={cdn.get('error')}")

    fofa = {"skipped": True} if args.skip_fofa else run_fofa(domain, size=args.fofa_size)
    print(f"[*] fofa assets={len(fofa.get('assets') or [])} skipped={fofa.get('skipped')}")

    dns = hist_dns(domain)
    print(f"[*] dns a={dns.get('a')}")

    # 新增：crt.sh / SPF/MX / SecurityTrails
    crt = {}
    if not args.skip_crt:
        print("[*] crt.sh cert transparency ...", flush=True)
        crt = crt_sh_lookup(domain)
        print(f"    ips={crt.get('ips')} alt_domains={len(crt.get('domains') or [])}")

    spf = {}
    if not args.skip_spf:
        print("[*] SPF/MX lookup ...", flush=True)
        spf = spf_mx_lookup(domain)
        print(f"    spf_ips={spf.get('ips')} mx_hosts={spf.get('mx_hosts')}")

    st = {}
    st_key = args.st_key or __import__("os").environ.get("SECURITYTRAILS_KEY", "")
    if st_key:
        print("[*] SecurityTrails historical DNS ...", flush=True)
        st = securitytrails_passive_dns(domain, api_key=st_key)
        print(f"    historical_a={st.get('historical_a')}")

    whois = {}
    whois_py = ENGINE / "tools" / "stdlib-kit" / "whois_lookup.py"
    if whois_py.is_file():
        print("[*] whois ...", flush=True)
        try:
            wr = subprocess.run(
                [sys.executable, str(whois_py), domain],
                capture_output=True, text=True, timeout=40, check=False,
            )
            whois = {"text": (wr.stdout or "").strip(), "rc": wr.returncode}
            (recon / "whois.txt").write_text(whois["text"] + "\n", encoding="utf-8")
        except Exception as exc:
            whois = {"error": str(exc)}

    extra = {
        "crt_ips": crt.get("ips") or [],
        "spf_ips": spf.get("ips") or [],
        "st_ips": st.get("historical_a") or [],
    }
    candidates = extract_candidates(cdn if isinstance(cdn, dict) else {}, fofa, dns, extra=extra)
    origin = {
        "generated_at": datetime.now(UTC).isoformat(),
        "domain": domain,
        "case": args.case,
        "cdn_tracer_file": str(cdn_out) if cdn_out.is_file() else None,
        "fofa": {k: v for k, v in fofa.items() if k != "assets"} | {"asset_count": len(fofa.get("assets") or [])},
        "fofa_assets": fofa.get("assets") or [],
        "dns": dns,
        "crt_sh": crt,
        "spf_mx": spf,
        "securitytrails": st,
        "whois": whois,
        "candidates": candidates,
        "non_cdn_candidates": [c for c in candidates if not c.get("cdn_likely")],
    }
    # 不把完整巨大 cdn 报告嵌进 origin；只留摘要
    if isinstance(cdn, dict):
        origin["cdn_summary"] = {
            "behind_cdn": (cdn.get("stage1_cdn") or {}).get("is_behind_cdn"),
            "detected": (cdn.get("stage1_cdn") or {}).get("all_detected_cdn"),
            "error": cdn.get("error"),
        }

    path = recon / "origin.json"
    path.write_text(json.dumps(origin, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    writeback_triage(args.case, origin)
    print(f"[+] {path}")
    print(f"    non_cdn={len(origin['non_cdn_candidates'])} total_cand={len(candidates)}")
    for c in origin["non_cdn_candidates"][:10]:
        print(f"    - {c['ip']} sources={c['sources']}")

    if args.with_space_search:
        ss = ENGINE / "tools" / "space-search" / "bin" / "space_search.py"
        if ss.is_file():
            print("[*] space_search cert-origin …")
            subprocess.run(
                [
                    sys.executable,
                    str(ss),
                    "cert-origin",
                    "--domain",
                    domain,
                    "--case",
                    args.case,
                ],
                check=False,
            )
        else:
            print(f"[!] missing {ss}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
