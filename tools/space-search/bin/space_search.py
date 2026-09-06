#!/usr/bin/env python3
"""网络空间测绘聚合：FOFA / Shodan / Censys / ZoomEye / Quake。

对齐 Playbook：传承/空间眼.md
密钥读 config.yaml（勿把 Key 写进案卷正文）。

示例:
  python3 tools/space-search/bin/space_search.py doctor
  python3 tools/space-search/bin/space_search.py cert-origin \\
    --domain example.com --case <案卷> --engines censys,fofa,zoomeye,quake,shodan
"""
from __future__ import annotations

import argparse
import base64
import json
import ssl
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

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT.parents[1]
OPS = _kit_ops_dir(Path(__file__))
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))

from scope_lib import host_of, in_scope  # noqa: E402

UA = "Mozilla/5.0 大爱仙尊-space_search"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def case_dir(case: str) -> Path:
    d = (ENGINE / "案卷" if (ENGINE / "案卷").is_dir() else ENGINE / "exports" / "bot-recovery") / case / "测绘" / "space_search"
    d.mkdir(parents=True, exist_ok=True)
    return d


def load_cfg() -> dict[str, Any]:
    try:
        import yaml  # type: ignore
    except Exception:
        yaml = None
    path = ENGINE / "config.yaml"
    if not path.is_file():
        return {}
    text = path.read_text(encoding="utf-8")
    if yaml:
        return yaml.safe_load(text) or {}
    # 极简回落
    return {}


def http_json(
    url: str,
    *,
    method: str = "GET",
    headers: dict | None = None,
    data: bytes | None = None,
    timeout: int = 45,
    basic: tuple[str, str] | None = None,
) -> dict[str, Any]:
    hdrs = {"User-Agent": UA, "Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    if basic:
        token = base64.b64encode(f"{basic[0]}:{basic[1]}".encode()).decode()
        hdrs["Authorization"] = f"Basic {token}"
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    ctx = ssl.create_default_context()
    # macOS/Python 偶发缺本地 CA；测绘 API 走降级校验以免整链断掉
    try:
        import certifi  # type: ignore

        ctx = ssl.create_default_context(cafile=certifi.where())
    except Exception:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
            raw = r.read()[:3_000_000]
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


def censys_auth(cfg: dict) -> dict[str, str]:
    """返回 Censys 鉴权信息：优先 Platform PAT，其次 Legacy api_id/secret。"""
    c = cfg.get("censys") or {}
    token = (c.get("api_token") or c.get("personal_access_token") or c.get("token") or "").strip()
    org = (c.get("organization_id") or c.get("org_id") or "").strip()
    api_id = (c.get("api_id") or "").strip()
    secret = (c.get("api_secret") or "").strip()
    if token:
        return {"mode": "pat", "token": token, "organization_id": org}
    if api_id and secret:
        return {"mode": "legacy", "api_id": api_id, "api_secret": secret, "organization_id": org}
    return {"mode": "none"}


def eng_status(cfg: dict) -> dict[str, Any]:
    f = cfg.get("fofa") or {}
    s = cfg.get("shodan") or {}
    z = cfg.get("zoomeye") or {}
    q = cfg.get("quake") or {}
    auth = censys_auth(cfg)
    return {
        "fofa": bool(f.get("key")),
        "shodan": bool(s.get("key")),
        "censys": auth.get("mode") in ("pat", "legacy"),
        "censys_mode": auth.get("mode"),
        "censys_org": bool(auth.get("organization_id")),
        "zoomeye": bool(z.get("api_key") or z.get("key")),
        "quake": bool(q.get("token") or q.get("key")),
    }


def search_fofa(cfg: dict, query: str, size: int = 50) -> dict[str, Any]:
    f = cfg.get("fofa") or {}
    key, email = f.get("key") or "", f.get("email") or ""
    if not key:
        return {"engine": "fofa", "skipped": True, "reason": "no key"}
    q64 = base64.b64encode(query.encode()).decode()
    fields = f.get("fields") or "host,ip,port,protocol,domain,title,server"
    params = urllib.parse.urlencode({"key": key, "email": email, "qbase64": q64, "size": size, "fields": fields})
    url = f"https://fofa.info/api/v1/search/all?{params}"
    r = http_json(url)
    j = r.get("json") or {}
    assets = []
    for row in j.get("results") or []:
        # fields order dependent
        if isinstance(row, list) and len(row) >= 3:
            assets.append({"host": row[0], "ip": row[1], "port": row[2], "raw": row[:8]})
        elif isinstance(row, dict):
            assets.append(row)
    return {"engine": "fofa", "query": query, "status": r.get("status"), "error": r.get("error") or j.get("errmsg"), "assets": assets, "count": len(assets)}


def search_shodan(cfg: dict, query: str, size: int = 50) -> dict[str, Any]:
    key = (cfg.get("shodan") or {}).get("key") or ""
    if not key:
        return {"engine": "shodan", "skipped": True, "reason": "no key"}
    params = urllib.parse.urlencode({"key": key, "query": query})
    url = f"https://api.shodan.io/shodan/host/search?{params}"
    r = http_json(url)
    j = r.get("json") or {}
    assets = []
    for m in (j.get("matches") or [])[:size]:
        assets.append({
            "ip": m.get("ip_str"),
            "port": m.get("port"),
            "host": (m.get("hostnames") or [None])[0],
            "org": m.get("org"),
            "product": m.get("product"),
        })
    return {"engine": "shodan", "query": query, "status": r.get("status"), "error": r.get("error") or j.get("error"), "assets": assets, "count": len(assets)}


def _censys_err(r: dict, j: dict | None = None) -> str | None:
    j = j if j is not None else (r.get("json") or {})
    if r.get("error"):
        detail = ""
        if isinstance(j, dict):
            detail = j.get("detail") or j.get("error") or ""
            if isinstance(detail, dict):
                detail = detail.get("message") or str(detail)
        return f"{r.get('error')}" + (f": {detail}" if detail else "")
    if isinstance(j, dict) and j.get("error"):
        return str(j.get("error"))
    if isinstance(j, dict) and j.get("detail") and r.get("status") not in (200, None):
        return str(j.get("detail"))
    return None


def _to_platform_query(query: str, *, cert: bool = False) -> str:
    """把旧 Legacy 语法尽量映射到 Platform CenQL；已是 host./cert. 前缀则原样。"""
    q = (query or "").strip()
    if q.startswith(("host.", "cert.", "web.", "dns.")):
        return q
    # Legacy hosts
    if "services.tls.certificates.leaf.names" in q:
        # services.tls.certificates.leaf.names: example.com
        name = q.split(":", 1)[-1].strip().strip('"').strip("'")
        return f'host.services.cert.names: "{name}"'
    if q.startswith("dns.names:"):
        name = q.split(":", 1)[-1].strip().strip('"').strip("'")
        return f'host.dns.names: "{name}"'
    # Legacy certs: names: example.com
    if cert or q.lower().startswith("names:"):
        name = q.split(":", 1)[-1].strip().strip('"').strip("'")
        return f'cert.names: "{name}"'
    return q


def _platform_resource(hit: dict) -> tuple[str, dict]:
    """从 Platform hit 抽出 (kind, resource)。常见键：host_v1 / certificate_v1 / web_property_v1。"""
    if not isinstance(hit, dict):
        return "", {}
    for key, kind in (
        ("host_v1", "host"),
        ("host", "host"),
        ("certificate_v1", "cert"),
        ("certificate", "cert"),
        ("web_property_v1", "web"),
        ("web_property", "web"),
    ):
        block = hit.get(key)
        if isinstance(block, dict):
            res = block.get("resource") if isinstance(block.get("resource"), dict) else block
            return kind, res
    if "ip" in hit:
        return "host", hit
    if hit.get("fingerprint_sha256") or hit.get("names"):
        return "cert", hit
    return "", hit


def _parse_platform_hits(j: dict, size: int) -> list[dict]:
    result = j.get("result") or j
    hits = result.get("hits") or []
    assets: list[dict] = []
    for hit in hits[:size]:
        if not isinstance(hit, dict):
            continue
        kind, res = _platform_resource(hit)
        if kind == "host" or res.get("ip"):
            ip = res.get("ip")
            services = res.get("services") or hit.get("matched_services") or []
            # matched_services 有时挂在 host_v1 同级
            if not services:
                for key in ("host_v1", "host"):
                    blk = hit.get(key) or {}
                    if isinstance(blk, dict) and blk.get("matched_services"):
                        services = blk.get("matched_services") or []
                        break
            ports = [s.get("port") for s in services if isinstance(s, dict) and s.get("port") is not None]
            as_name = ((res.get("autonomous_system") or {}) or {}).get("name")
            if ip:
                assets.append({"ip": ip, "ports": ports, "autonomous_system": as_name})
            continue
        if kind == "cert" or res.get("fingerprint_sha256") or res.get("names"):
            parsed = res.get("parsed") if isinstance(res.get("parsed"), dict) else {}
            fp = res.get("fingerprint_sha256") or parsed.get("fingerprint_sha256")
            names = res.get("names") or parsed.get("names") or []
            assets.append({"fingerprint_sha256": fp, "names": names[:20], "ip": None})
    return assets


def search_censys_hosts(cfg: dict, query: str, size: int = 50) -> dict[str, Any]:
    auth = censys_auth(cfg)
    if auth.get("mode") == "none":
        return {"engine": "censys", "skipped": True, "reason": "no api_token or api_id/api_secret"}

    # Platform PAT
    if auth.get("mode") == "pat":
        org = auth.get("organization_id") or ""
        if not org:
            return {
                "engine": "censys",
                "skipped": True,
                "reason": "missing organization_id（付费组织 UUID，见 accounts.censys.io PAT 页 Current Organization）",
                "query": query,
            }
        pq = _to_platform_query(query, cert=False)
        body = json.dumps({"query": pq, "page_size": min(size, 100)}).encode()
        url = "https://api.platform.censys.io/v3/global/search/query?" + urllib.parse.urlencode(
            {"organization_id": org}
        )
        r = http_json(
            url,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {auth['token']}",
                "X-Organization-ID": org,
            },
            data=body,
        )
        j = r.get("json") or {}
        assets = [a for a in _parse_platform_hits(j, size) if a.get("ip")]
        return {
            "engine": "censys",
            "query": pq,
            "status": r.get("status"),
            "error": _censys_err(r, j),
            "assets": assets,
            "count": len(assets),
            "api": "platform",
        }

    # Legacy Basic
    api_id, secret = auth["api_id"], auth["api_secret"]
    body = json.dumps({"q": query, "per_page": min(size, 100)}).encode()
    r = http_json(
        "https://search.censys.io/api/v2/hosts/search",
        method="POST",
        headers={"Content-Type": "application/json"},
        data=body,
        basic=(api_id, secret),
    )
    j = r.get("json") or {}
    result = j.get("result") or {}
    assets = []
    for hit in (result.get("hits") or [])[:size]:
        ip = hit.get("ip")
        services = hit.get("services") or []
        ports = [s.get("port") for s in services if isinstance(s, dict)]
        assets.append(
            {
                "ip": ip,
                "ports": ports,
                "name": hit.get("name"),
                "autonomous_system": (hit.get("autonomous_system") or {}).get("name"),
            }
        )
    return {
        "engine": "censys",
        "query": query,
        "status": r.get("status"),
        "error": _censys_err(r, j),
        "assets": assets,
        "count": len(assets),
        "api": "legacy",
    }


def search_censys_certs(cfg: dict, query: str, size: int = 25) -> dict[str, Any]:
    auth = censys_auth(cfg)
    if auth.get("mode") == "none":
        return {"engine": "censys_certs", "skipped": True, "reason": "no api_token or api_id/api_secret"}

    if auth.get("mode") == "pat":
        org = auth.get("organization_id") or ""
        if not org:
            return {
                "engine": "censys_certs",
                "skipped": True,
                "reason": "missing organization_id",
                "query": query,
            }
        pq = _to_platform_query(query, cert=True)
        body = json.dumps({"query": pq, "page_size": min(size, 100)}).encode()
        url = "https://api.platform.censys.io/v3/global/search/query?" + urllib.parse.urlencode(
            {"organization_id": org}
        )
        r = http_json(
            url,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {auth['token']}",
                "X-Organization-ID": org,
            },
            data=body,
        )
        j = r.get("json") or {}
        parsed = _parse_platform_hits(j, size)
        certs = []
        hosts_by_cert = []
        for a in parsed:
            if a.get("fingerprint_sha256") or a.get("names"):
                certs.append(
                    {
                        "fingerprint_sha256": a.get("fingerprint_sha256"),
                        "names": a.get("names") or [],
                    }
                )
            elif a.get("ip"):
                # 证书查询也可能直接返回关联 host
                hosts_by_cert.append(
                    {"fingerprint_sha256": None, "hosts": [a["ip"]], "status": r.get("status")}
                )
        return {
            "engine": "censys_certs",
            "query": pq,
            "status": r.get("status"),
            "error": _censys_err(r, j),
            "certs": certs,
            "hosts_by_cert": hosts_by_cert,
            "count": len(certs) or len(hosts_by_cert),
            "api": "platform",
        }

    api_id, secret = auth["api_id"], auth["api_secret"]
    body = json.dumps({"q": query, "per_page": min(size, 100)}).encode()
    r = http_json(
        "https://search.censys.io/api/v2/certificates/search",
        method="POST",
        headers={"Content-Type": "application/json"},
        data=body,
        basic=(api_id, secret),
    )
    j = r.get("json") or {}
    result = j.get("result") or {}
    certs = []
    for hit in (result.get("hits") or [])[:size]:
        parsed = hit.get("parsed") or {}
        fp = hit.get("fingerprint_sha256") or parsed.get("fingerprint_sha256")
        names = parsed.get("names") or hit.get("names") or []
        certs.append({"fingerprint_sha256": fp, "names": names[:20], "issuer": (parsed.get("issuer_dn") or "")[:120]})
    hosts_by_cert = []
    for cert in certs[:5]:
        fp = cert.get("fingerprint_sha256")
        if not fp:
            continue
        hr = http_json(
            f"https://search.censys.io/api/v2/certificates/{fp}/hosts",
            basic=(api_id, secret),
        )
        hj = hr.get("json") or {}
        hosts = (hj.get("result") or {}).get("hosts") or hj.get("hosts") or []
        ips = []
        if isinstance(hosts, list):
            for h in hosts[:30]:
                if isinstance(h, str):
                    ips.append(h.split(":")[0])
                elif isinstance(h, dict):
                    ips.append(h.get("ip") or h.get("host") or "")
        hosts_by_cert.append({"fingerprint_sha256": fp, "hosts": [x for x in ips if x], "status": hr.get("status")})
    return {
        "engine": "censys_certs",
        "query": query,
        "status": r.get("status"),
        "error": _censys_err(r, j),
        "certs": certs,
        "hosts_by_cert": hosts_by_cert,
        "count": len(certs),
        "api": "legacy",
    }


def search_zoomeye(cfg: dict, query: str, size: int = 20) -> dict[str, Any]:
    z = cfg.get("zoomeye") or {}
    key = z.get("api_key") or z.get("key") or ""
    if not key:
        return {"engine": "zoomeye", "skipped": True, "reason": "no api_key"}
    q64 = base64.b64encode(query.encode()).decode()
    body = json.dumps({"qbase64": q64, "page": 1, "pagesize": min(size, 100)}).encode()
    # 新 API
    r = http_json(
        "https://api.zoomeye.ai/v2/search",
        method="POST",
        headers={"API-KEY": key, "Content-Type": "application/json"},
        data=body,
    )
    # 旧 API 回落
    if r.get("status") in (0, 404, 401, 403) or (r.get("status") != 200 and not (r.get("json") or {}).get("data")):
        q = urllib.parse.quote(query)
        r2 = http_json(
            f"https://api.zoomeye.org/host/search?query={q}&page=1",
            headers={"API-KEY": key},
        )
        if r2.get("status") == 200:
            r = r2
    j = r.get("json") or {}
    data = j.get("data") or j.get("matches") or []
    assets = []
    for m in data[:size]:
        if not isinstance(m, dict):
            continue
        assets.append({
            "ip": m.get("ip") or m.get("ipaddress"),
            "port": m.get("port"),
            "domain": m.get("domain"),
            "title": m.get("title"),
        })
    return {"engine": "zoomeye", "query": query, "status": r.get("status"), "error": r.get("error") or j.get("message"), "assets": assets, "count": len(assets)}


def search_quake(cfg: dict, query: str, size: int = 20) -> dict[str, Any]:
    qcfg = cfg.get("quake") or {}
    token = qcfg.get("token") or qcfg.get("key") or ""
    if not token:
        return {"engine": "quake", "skipped": True, "reason": "no token"}
    body = json.dumps({"query": query, "start": 0, "size": min(size, 100)}).encode()
    r = http_json(
        "https://quake.360.net/api/v3/search/quake_service",
        method="POST",
        headers={"X-QuakeToken": token, "Content-Type": "application/json"},
        data=body,
    )
    j = r.get("json") or {}
    data = j.get("data") or []
    assets = []
    for m in data[:size]:
        if not isinstance(m, dict):
            continue
        assets.append({
            "ip": m.get("ip"),
            "port": m.get("port"),
            "hostname": m.get("hostname") or ((m.get("service") or {}).get("http") or {}).get("host"),
            "title": ((m.get("service") or {}).get("http") or {}).get("title"),
        })
    code = j.get("code")
    err = r.get("error")
    if code not in (None, 0, "0") and not assets:
        err = err or j.get("message") or f"quake code={code}"
    return {"engine": "quake", "query": query, "status": r.get("status"), "error": err, "assets": assets, "count": len(assets)}


def merge_ips(*results: dict) -> list[dict]:
    bag: dict[str, dict] = {}
    for res in results:
        if not res or res.get("skipped"):
            continue
        eng = res.get("engine") or "?"
        for a in res.get("assets") or []:
            ip = a.get("ip")
            if not ip:
                continue
            e = bag.setdefault(ip, {"ip": ip, "engines": [], "ports": set(), "meta": []})
            if eng not in e["engines"]:
                e["engines"].append(eng)
            port = a.get("port")
            if port:
                e["ports"].add(int(port) if str(port).isdigit() else port)
            e["meta"].append({k: a.get(k) for k in ("host", "hostname", "domain", "title", "org") if a.get(k)})
        for block in res.get("hosts_by_cert") or []:
            for ip in block.get("hosts") or []:
                e = bag.setdefault(ip, {"ip": ip, "engines": [], "ports": set(), "meta": []})
                if "censys_certs" not in e["engines"]:
                    e["engines"].append("censys_certs")
                e["meta"].append({"fingerprint": block.get("fingerprint_sha256")})
    out = []
    for ip, e in bag.items():
        out.append({
            "ip": ip,
            "engines": e["engines"],
            "ports": sorted(e["ports"], key=lambda x: str(x)),
            "meta": e["meta"][:5],
            "engine_count": len(e["engines"]),
        })
    out.sort(key=lambda x: (-x["engine_count"], x["ip"]))
    return out


def cmd_doctor(_: argparse.Namespace) -> int:
    cfg = load_cfg()
    st = eng_status(cfg)
    auth = censys_auth(cfg)
    live: dict[str, Any] = {}
    if auth.get("mode") == "pat":
        # 轻量探活：免费钱包积分（不耗搜索额度）
        r = http_json(
            "https://api.platform.censys.io/v3/accounts/users/credits",
            headers={"Authorization": f"Bearer {auth['token']}"},
        )
        j = r.get("json") or {}
        bal = (j.get("result") or {}).get("balance")
        live["censys_pat"] = {"status": r.get("status"), "free_wallet_balance": bal, "error": _censys_err(r, j)}
        if auth.get("organization_id"):
            org = auth["organization_id"]
            or_url = f"https://api.platform.censys.io/v3/accounts/organizations/{org}/credits"
            rr = http_json(or_url, headers={"Authorization": f"Bearer {auth['token']}"})
            jj = rr.get("json") or {}
            live["censys_org"] = {
                "organization_id": org,
                "status": rr.get("status"),
                "balance": (jj.get("result") or {}).get("balance"),
                "error": _censys_err(rr, jj),
            }
        else:
            live["censys_org"] = {
                "configured": False,
                "hint": "付费搜索需 organization_id：accounts.censys.io → Personal Access Tokens → Current Organization",
            }
    print(
        json.dumps(
            {
                "ts": _now(),
                "engines_configured": {k: v for k, v in st.items() if not k.startswith("_")},
                "live": live,
                "hint": "缺的引擎见下方 [need]；Censys 需 api_token+organization_id",
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    key_flags = {k: st[k] for k in ("fofa", "shodan", "censys", "zoomeye", "quake")}
    missing = [k for k, v in key_flags.items() if not v]
    if st.get("censys") and not st.get("censys_org") and auth.get("mode") == "pat":
        print("[warn] Censys PAT 已写入，但缺 organization_id — 搜索 API 会按免费档拒绝")
    if missing:
        print(f"[need] 待补 Key: {', '.join(missing)}")
        print("  Censys: accounts.censys.io/settings/personal-access-tokens（PAT + Organization ID）")
        print("  ZoomEye: www.zoomeye.ai/profile")
        print("  Quake: quake.360.net (用户信息 / API Token)")
    else:
        print("[ok] 五引擎 Key 均已配置")
    return 0


def cmd_search(args: argparse.Namespace) -> int:
    cfg = load_cfg()
    engines = [e.strip() for e in (args.engines or "fofa,shodan,censys,zoomeye,quake").split(",") if e.strip()]
    results = []
    for eng in engines:
        if eng == "fofa":
            results.append(search_fofa(cfg, args.query, args.size))
        elif eng == "shodan":
            results.append(search_shodan(cfg, args.query, args.size))
        elif eng == "censys":
            results.append(search_censys_hosts(cfg, args.query, args.size))
        elif eng == "zoomeye":
            results.append(search_zoomeye(cfg, args.query, args.size))
        elif eng == "quake":
            results.append(search_quake(cfg, args.query, args.size))
        else:
            print(f"[skip] unknown engine {eng}")
        r = results[-1]
        print(f"  [{eng}] status={r.get('status')} count={r.get('count')} skipped={r.get('skipped')} err={r.get('error')}")
    merged = merge_ips(*results)
    out = {"ts": _now(), "query": args.query, "engines": engines, "results": results, "merged_ips": merged}
    if args.case:
        path = case_dir(args.case) / "search.json"
        path.write_text(json.dumps(out, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"[ok] -> {path}")
    else:
        print(json.dumps({"merged_ips": merged[:30]}, ensure_ascii=False, indent=2))
    return 0


def cmd_cert_origin(args: argparse.Namespace) -> int:
    domain = host_of(args.domain)
    if not args.skip_scope and not in_scope(domain):
        raise SystemExit(f"[scope] {domain} 不在授权范围")
    cfg = load_cfg()
    engines = [e.strip() for e in (args.engines or "censys,fofa,zoomeye,quake,shodan").split(",") if e.strip()]

    # 各引擎「证书/域名」语法（CDN 旁路常用）
    queries = {
        "fofa": [f'cert="{domain}"', f'domain="{domain}"', f'host="{domain}"'],
        "shodan": [f'ssl.cert.subject.CN:{domain}', f'hostname:{domain}'],
        "censys": [f'services.tls.certificates.leaf.names: {domain}', f'dns.names: {domain}'],
        "censys_certs": [f'names: {domain}'],
        "zoomeye": [f'ssl:"{domain}"', f'hostname:"{domain}"'],
        "quake": [f'cert:"{domain}"', f'domain:"{domain}"'],
    }

    results = []
    for eng in engines:
        if eng == "censys":
            for q in queries["censys"]:
                results.append(search_censys_hosts(cfg, q, args.size))
            for q in queries["censys_certs"]:
                results.append(search_censys_certs(cfg, q, min(args.size, 25)))
        elif eng == "fofa":
            for q in queries["fofa"]:
                results.append(search_fofa(cfg, q, args.size))
        elif eng == "shodan":
            for q in queries["shodan"]:
                results.append(search_shodan(cfg, q, args.size))
        elif eng == "zoomeye":
            for q in queries["zoomeye"]:
                results.append(search_zoomeye(cfg, q, args.size))
        elif eng == "quake":
            for q in queries["quake"]:
                results.append(search_quake(cfg, q, args.size))
        for r in results[-3:]:
            if r.get("engine") in (eng, "censys_certs") or eng == "censys":
                print(f"  [{r.get('engine')}] q={r.get('query')!r} count={r.get('count')} skipped={r.get('skipped')} err={r.get('error')}")

    merged = merge_ips(*results)
    report = {
        "ts": _now(),
        "pattern": "cert-cdn-origin",
        "domain": domain,
        "ref": "CSDN VoltCary Censys SSL→源站；引擎表 Shodan/Censys/FOFA/ZoomEye/Quake",
        "engines_requested": engines,
        "engines_configured": eng_status(cfg),
        "results": results,
        "merged_ips": merged,
        "note": "候选需 HTTP Host 头验证再当源站；共享 CDN 证书易误报",
    }
    out = case_dir(args.case)
    path = out / "cert_origin.json"
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    md = out / "CERT_ORIGIN.md"
    lines = [
        f"# 证书/空间引擎溯源 — {domain}",
        "",
        f"- 时间: {report['ts']}",
        f"- 合并 IP: {len(merged)}",
        "",
        "## Top 候选",
        "",
    ]
    for m in merged[:30]:
        lines.append(f"- `{m['ip']}` engines={','.join(m['engines'])} ports={m['ports']}")
    lines += ["", f"详表: `{path.name}`", ""]
    md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[ok] merged={len(merged)} -> {path}")
    for m in merged[:15]:
        print(f"  - {m['ip']} [{','.join(m['engines'])}]")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="空间测绘聚合 FOFA/Shodan/Censys/ZoomEye/Quake")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("doctor", help="检查 config.yaml 五引擎 Key")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("search", help="单查询多引擎")
    p.add_argument("--query", required=True)
    p.add_argument("--engines", default="fofa,shodan,censys,zoomeye,quake")
    p.add_argument("--size", type=int, default=30)
    p.add_argument("--case", default="")
    p.set_defaults(func=cmd_search)

    p = sub.add_parser("cert-origin", help="CDN/证书旁路：按域名打证书相关语法")
    p.add_argument("--domain", required=True)
    p.add_argument("--case", required=True)
    p.add_argument("--engines", default="censys,fofa,zoomeye,quake,shodan")
    p.add_argument("--size", type=int, default=30)
    p.add_argument("--skip-scope", action="store_true")
    p.set_defaults(func=cmd_cert_origin)

    args = ap.parse_args()
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
