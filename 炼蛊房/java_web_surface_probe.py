#!/usr/bin/env python3
"""
java_web_surface_probe.py — 网站向 Java 管理面快速分流（授权范围内）

探测栈：Jeecg-Boot / Shiro rememberMe（L1 指纹 + L2 弱密钥碰撞） / Druid / XXL-JOB / 国产 OA(cnoa)
默认只做指纹 + 未授权读 / 弱口令登录页探测 / Shiro 密钥碰撞（看 deleteMe 是否消失）。
不下发反序列化 gadget / 不连 JDBC。cnoa 只 GET，正文无针不算命中。

用法：
  python3 炼蛊房/java_web_surface_probe.py -u https://授权站 --case <案卷>
  python3 炼蛊房/java_web_surface_probe.py -u https://授权站 --stack cnoa
  python3 炼蛊房/java_web_surface_probe.py -u https://授权站 --stack jeecg,druid
  python3 炼蛊房/java_web_surface_probe.py -u https://授权站 --out /tmp/jw.json
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
from datetime import datetime, UTC
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

try:
    import requests
    requests.packages.urllib3.disable_warnings()  # type: ignore
except ImportError:
    print("[!] pip install requests", file=sys.stderr)
    sys.exit(1)

ROOT = Path(__file__).resolve().parents[1]
OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import require_in_scope  # noqa: E402
ALL_STACKS = ("jeecg", "shiro", "druid", "xxljob", "cnoa")


def _sess() -> requests.Session:
    s = requests.Session()
    s.verify = False
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (compatible; 大爱仙尊-JavaWeb/1.0)",
        "Accept": "text/html,application/json,*/*",
    })
    return s


def _req(sess: requests.Session, method: str, url: str, **kw) -> requests.Response | None:
    kw.setdefault("timeout", 12)
    kw.setdefault("verify", False)
    kw.setdefault("allow_redirects", True)
    try:
        return sess.request(method, url, **kw)
    except Exception:
        return None


def _hit(finding: dict[str, Any], findings: list[dict[str, Any]]) -> None:
    findings.append(finding)


def probe_jeecg(sess: requests.Session, base: str, findings: list[dict[str, Any]]) -> None:
    paths = [
        "/",
        "/jeecg-boot/",
        "/jeecg-boot/sys/randomImage/probe",
        "/sys/randomImage/probe",
    ]
    for p in paths:
        r = _req(sess, "GET", urljoin(base, p))
        if not r:
            continue
        body = r.text[:6000]
        if any(x in body for x in ("Jeecg", "jeecg-boot", "JeecgBoot", "window._CONFIG", "_CONFIG['domianURL']")):
            _hit({
                "stack": "jeecg",
                "level": "L1",
                "path": p,
                "status": r.status_code,
                "signal": "product-fingerprint",
            }, findings)
            break

    for p in (
        "/jeecg-boot/sys/dict/getDictItems/sex",
        "/sys/dict/getDictItems/sex",
    ):
        r = _req(sess, "GET", urljoin(base, p))
        if not r or r.status_code != 200:
            continue
        if '"success"' in r.text or '"result"' in r.text:
            _hit({
                "stack": "jeecg",
                "level": "L2",
                "path": p,
                "status": r.status_code,
                "signal": "dict-unauth-suspect",
                "snippet": r.text[:200],
            }, findings)

    for user, pwd in (("admin", "123456"), ("jeecg", "123456")):
        r = _req(
            sess, "POST", urljoin(base, "/jeecg-boot/sys/login"),
            json={"username": user, "password": pwd, "captcha": "", "checkKey": ""},
            headers={"Content-Type": "application/json"},
        )
        if not r:
            continue
        if r.status_code == 200 and ("token" in r.text.lower() or '"success":true' in r.text.replace(" ", "")):
            if "验证码" in r.text or "captcha" in r.text.lower() and "token" not in r.text.lower():
                continue
            _hit({
                "stack": "jeecg",
                "level": "L2",
                "path": "/jeecg-boot/sys/login",
                "status": r.status_code,
                "signal": f"weak-login-suspect:{user}",
            }, findings)
            break


# 空 SimplePrincipalCollection 的 Java 序列化（公开检测用，非 gadget / 非 RCE）。
# 错钥 → 解密失败 → deleteMe；对钥 → 反序列化成功 → 不再下发 deleteMe。
_SHIRO_CHECK_PLAIN = base64.b64decode(
    "rO0ABXNyADJvcmcuYXBhY2hlLnNoaXJvLnN1YmplY3QuU2ltcGxlUHJpbmNpcGFsQ29sbGVjdGlv"
    "bqh/WKXGhaI9AgABTAAPcmVhbG1QcmluY2lwYWxzdAAPTGphdmEvdXRpbC9NYXA7eHBwdwEAeHg="
)


def _set_cookie_blob(r: requests.Response) -> str:
    raw = getattr(r.raw, "headers", None)
    if raw is not None and hasattr(raw, "get_all"):
        try:
            vals = raw.get_all("Set-Cookie") or []
        except TypeError:
            vals = []
        if vals:
            return ";".join(vals)
    sc = r.headers.get("Set-Cookie", "") or ""
    if hasattr(r.headers, "getlist"):
        return ";".join(r.headers.getlist("Set-Cookie"))  # type: ignore
    joined = ";".join(v for k, v in r.headers.items() if k.lower() == "set-cookie")
    return joined or sc


def _has_deleteme(r: requests.Response | None) -> bool:
    if not r:
        return False
    try:
        if r.cookies.get("rememberMe") == "deleteMe":
            return True
    except Exception:
        pass
    blob = _set_cookie_blob(r)
    return "rememberMe=deleteMe" in blob


def _mask_key(b64: str) -> str:
    s = b64.strip()
    if len(s) <= 8:
        return s[:2] + "…"
    return s[:4] + "…" + s[-4:]


def _crypto_ok() -> bool:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher  # noqa: F401
        return True
    except ImportError:
        return False


def _load_shiro_keys(keys_file: Path | None, max_keys: int) -> tuple[list[str], str]:
    """返回 (keys, note)。note 非空表示字典路径有问题。"""
    note = ""
    candidates: list[Path] = []
    if keys_file is not None:
        if keys_file.exists():
            candidates.append(keys_file)
        else:
            note = f"keys-file-missing:{keys_file}"
            return [], note
    else:
        priv = ROOT / "dict" / "shiro_aes_keys.txt"
        example = ROOT / "dict" / "shiro_aes_keys.example.txt"
        if priv.exists():
            candidates.append(priv)
        elif example.exists():
            candidates.append(example)
    keys: list[str] = []
    seen: set[str] = set()
    for path in candidates:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line in seen:
                continue
            seen.add(line)
            keys.append(line)
            if len(keys) >= max_keys:
                return keys, note
    return keys, note


def _shiro_rememberme_cookie(key_b64: str) -> str | None:
    """AES-CBC 加密空 PrincipalCollection，用于弱密钥碰撞（非 gadget / 非 RCE）。"""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding as sympad
    except ImportError:
        return None
    try:
        key = base64.b64decode(key_b64)
    except Exception:
        return None
    if len(key) not in (16, 24, 32):
        return None
    iv = os.urandom(16)
    padder = sympad.PKCS7(128).padder()
    pt = padder.update(_SHIRO_CHECK_PLAIN) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct = enc.update(pt) + enc.finalize()
    return base64.b64encode(iv + ct).decode("ascii")


def _shiro_get(sess: requests.Session, url: str, remember_val: str) -> requests.Response | None:
    """用 cookies= 下发 rememberMe，避免 Session Cookie 头覆盖探测值。"""
    sess.cookies.clear()
    return _req(sess, "GET", url, cookies={"rememberMe": remember_val})


def probe_shiro(
    sess: requests.Session,
    base: str,
    findings: list[dict[str, Any]],
    *,
    key_check: bool = True,
    keys_file: Path | None = None,
    max_keys: int = 40,
) -> None:
    paths = ["/", "/login", "/jeecg-boot/", "/prod-api/login", "/api/login"]
    l1_path: str | None = None
    for p in paths:
        r = _shiro_get(sess, urljoin(base, p), "1")
        if not r:
            continue
        if _has_deleteme(r):
            l1_path = p
            _hit({
                "stack": "shiro",
                "level": "L1",
                "path": p,
                "status": r.status_code,
                "signal": "rememberMe=deleteMe",
            }, findings)
            break
    if not l1_path or not key_check:
        return

    keys, dict_note = _load_shiro_keys(keys_file, max_keys)
    if not keys:
        _hit({
            "stack": "shiro",
            "level": "L2-skip",
            "path": l1_path,
            "signal": dict_note or "no-key-dict",
            "note": "复制 dict/shiro_aes_keys.example.txt → dict/shiro_aes_keys.txt 后重跑",
        }, findings)
        return

    if not _crypto_ok():
        _hit({
            "stack": "shiro",
            "level": "L2-skip",
            "path": l1_path,
            "signal": "cryptography-missing",
            "note": "pip install cryptography 后重跑 L2",
        }, findings)
        return

    url = urljoin(base, l1_path)
    junk = _shiro_get(sess, url, "1")
    if not _has_deleteme(junk):
        _hit({
            "stack": "shiro",
            "level": "L2-skip",
            "path": l1_path,
            "signal": "deleteme-unstable",
            "note": "L1 后 junk cookie 不再回 deleteMe，放弃碰撞以免误报",
        }, findings)
        return

    for key_b64 in keys:
        cookie_val = _shiro_rememberme_cookie(key_b64)
        if not cookie_val:
            continue
        r = _shiro_get(sess, url, cookie_val)
        if not r or _has_deleteme(r):
            continue
        confirm = _shiro_get(sess, url, "1")
        if not _has_deleteme(confirm):
            _hit({
                "stack": "shiro",
                "level": "L2-skip",
                "path": l1_path,
                "signal": "deleteme-unstable",
                "note": "疑似 WAF/CDN 吞 Set-Cookie，不记弱密钥命中",
            }, findings)
            return
        _hit({
            "stack": "shiro",
            "level": "L2",
            "path": l1_path,
            "status": r.status_code,
            "signal": "weak-key-hit",
            "key_fp": _mask_key(key_b64),
            "note": "完整 key 打码后手落案卷；L3 反序列化先问",
        }, findings)
        return
    _hit({
        "stack": "shiro",
        "level": "L2-miss",
        "path": l1_path,
        "signal": "no-key-in-dict",
        "tried": len(keys),
        "note": "扩私有字典或转 Jeecg/Druid/Actuator，勿空撞",
    }, findings)


def probe_druid(sess: requests.Session, base: str, findings: list[dict[str, Any]]) -> None:
    prefixes = ["", "/prod-api", "/api", "/admin"]
    login_hit = None
    for pref in prefixes:
        p = f"{pref}/druid/login.html"
        r = _req(sess, "GET", urljoin(base, p))
        if not r or r.status_code >= 400:
            continue
        if re.search(r"druid|statview|login\.html", r.text, re.I):
            login_hit = pref
            _hit({
                "stack": "druid",
                "level": "L1",
                "path": p,
                "status": r.status_code,
                "signal": "login.html",
            }, findings)
            break

    if login_hit is None:
        return

    for user, pwd, tag in (
        ("ruoyi", "123456", "ruoyi"),
        ("admin", "admin", "admin"),
        ("druid", "druid", "druid"),
    ):
        r = _req(
            sess, "POST", urljoin(base, f"{login_hit}/druid/submitLogin"),
            data={"loginUsername": user, "loginPassword": pwd},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if r and "success" in (r.text or "").lower():
            _hit({
                "stack": "druid",
                "level": "L2",
                "path": f"{login_hit}/druid/submitLogin",
                "status": r.status_code,
                "signal": f"weak-login:{tag}",
            }, findings)
            # try datasource hint without dumping secrets
            ds = _req(sess, "GET", urljoin(base, f"{login_hit}/druid/datasource.json"))
            if ds and ds.status_code == 200 and "jdbc" in ds.text.lower():
                _hit({
                    "stack": "druid",
                    "level": "L3-hint",
                    "path": f"{login_hit}/druid/datasource.json",
                    "status": ds.status_code,
                    "signal": "datasource-json-reachable",
                    "note": "含 JDBC；完整凭据打码后手落案卷",
                }, findings)
            return


def probe_xxljob(sess: requests.Session, base: str, findings: list[dict[str, Any]]) -> None:
    for p in ("/xxl-job-admin/toLogin", "/xxl-job-admin/", "/toLogin"):
        r = _req(sess, "GET", urljoin(base, p))
        if not r:
            continue
        if "XXL-JOB" in r.text or "xxl-job-admin" in r.text:
            _hit({
                "stack": "xxljob",
                "level": "L1",
                "path": p,
                "status": r.status_code,
                "signal": "admin-ui",
            }, findings)
            r2 = _req(
                sess, "POST", urljoin(base, "/xxl-job-admin/login"),
                data={"userName": "admin", "password": "123456"},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                allow_redirects=False,
            )
            cookie = (r2.headers.get("Set-Cookie", "") if r2 else "")
            loc = (r2.headers.get("Location", "") if r2 else "").lower()
            body_ok = bool(r2 and '"code":200' in r2.text.replace(" ", ""))
            cookie_ok = "XXL_JOB_LOGIN_IDENTITY" in cookie or bool(
                r2 and (r2.cookies.get("XXL_JOB_LOGIN_IDENTITY") or sess.cookies.get("XXL_JOB_LOGIN_IDENTITY"))
            )
            loc_ok = bool(
                r2 and r2.status_code in {301, 302, 303}
                and "tologin" not in loc
                and (loc.rstrip("/").endswith("index") or "/index?" in loc or "/index/" in loc)
            )
            if body_ok or cookie_ok or loc_ok:
                _hit({
                    "stack": "xxljob",
                    "level": "L2",
                    "path": "/xxl-job-admin/login",
                    "status": r2.status_code if r2 else None,
                    "signal": "weak-login:admin",
                    "next": "python3 炼蛊房/xxljob_admin_probe.py --base " + base,
                }, findings)
            return


def probe_cnoa(sess: requests.Session, base: str, findings: list[dict[str, Any]]) -> None:
    """国产 OA / 若依指纹（只 GET，不发利用）。"""
    probes = (
        ("/seeyon/", "seeyon", ("seeyon", "致远")),
        ("/seeyon/login.jsp", "seeyon", ("seeyon", "login")),
        ("/logincheck.php", "tongda", ("logincheck", "tongda", "office")),
        ("/weaver/", "weaver", ("weaver", "ecology", "泛微")),
        ("/ecology/", "weaver", ("ecology", "weaver")),
        ("/nc/", "yonyou", ("yonyou", "用友", "nc")),
        ("/nccloud/", "yonyou", ("nccloud", "yonyou", "用友")),
        ("/prod-api/", "ruoyi", ("ruoyi", "若依", "captcha")),
        ("/ekp/", "landray", ("landray", "蓝凌", "ekp")),
    )
    for path, stack, needles in probes:
        r = _req(sess, "GET", urljoin(base, path))
        if not r or r.status_code >= 400:
            continue
        body = (r.text or "")[:4000].lower()
        if not any(n.lower() in body for n in needles):
            continue
        _hit({
            "stack": f"cnoa:{stack}",
            "level": "L1",
            "path": path,
            "status": r.status_code,
            "signal": "cn-oa-fingerprint",
        }, findings)


PLAYBOOK = {
    "jeecg": "传承/济世·无门.md",
    "shiro": "传承/记忆蛊.md",
    "druid": "传承/仓算·监.md",
    "xxljob": "传承/差事府·无门.md",
    "cnoa": "智道藏书/智道推演/techniques/中原骨架.md",
    "cnoa:seeyon": "传承/官衙·用友致远.md",
    "cnoa:yonyou": "传承/官衙·用友致远.md",
    "cnoa:ruoyi": "传承/若依四海杀伤链.md",
    "cnoa:tongda": "智道藏书/智道推演/techniques/中原骨架.md",
    "cnoa:weaver": "智道藏书/智道推演/techniques/中原骨架.md",
    "cnoa:landray": "智道藏书/智道推演/techniques/中原骨架.md",
}


def run(
    base_url: str,
    stacks: list[str],
    case: str,
    out: Path | None,
    *,
    shiro_key_check: bool = True,
    shiro_keys_file: Path | None = None,
    shiro_max_keys: int = 40,
) -> dict[str, Any]:
    base = base_url.rstrip("/") + "/"
    host = urlparse(base).hostname or ""
    if host:
        require_in_scope(host)

    sess = _sess()
    findings: list[dict[str, Any]] = []
    for st in stacks:
        if st == "jeecg":
            probe_jeecg(sess, base, findings)
        elif st == "shiro":
            probe_shiro(
                sess, base, findings,
                key_check=shiro_key_check,
                keys_file=shiro_keys_file,
                max_keys=shiro_max_keys,
            )
        elif st == "druid":
            probe_druid(sess, base, findings)
        elif st == "xxljob":
            probe_xxljob(sess, base, findings)
        elif st == "cnoa":
            probe_cnoa(sess, base, findings)

    report = {
        "target": base_url,
        "ts": datetime.now(UTC).isoformat(),
        "stacks": stacks,
        "findings": findings,
        "playbooks": {s: PLAYBOOK[s] for s in stacks if s in PLAYBOOK},
        "next": [],
    }
    seen = {f["stack"] for f in findings}
    for s in seen:
        pb = PLAYBOOK.get(s) or PLAYBOOK.get(s.split(":")[0], "")
        if pb:
            report["next"].append(pb)

    text = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    written: list[Path] = []
    if case:
        case_dir = ROOT / "案卷" / case / "测绘" / "java_web"
        case_dir.mkdir(parents=True, exist_ok=True)
        p = case_dir / "surface.json"
        p.write_text(text, encoding="utf-8")
        written.append(p)
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        written.append(out)
    if not written:
        p = Path("java_web_surface.json")
        p.write_text(text, encoding="utf-8")
        written.append(p)
    out_path = written[-1] if out else written[0]

    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"\n[+] wrote {out_path}", file=sys.stderr)
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="Java 网站面分流探针（Jeecg/Shiro/Druid/XXL-JOB/国产OA）")
    ap.add_argument("-u", "--url", required=True, help="授权目标 base URL")
    ap.add_argument("--case", default="", help="案卷名 → 案卷/<case>/案卷/java_web/")
    ap.add_argument("--out", type=Path, default=None, help="自定义输出 JSON")
    ap.add_argument(
        "--stack",
        default="all",
        help="comma: jeecg,shiro,druid,xxljob,cnoa 或 all",
    )
    ap.add_argument("--no-shiro-keys", action="store_true", help="只做 L1 deleteMe，跳过弱密钥碰撞")
    ap.add_argument("--shiro-keys", type=Path, default=None, help="密钥字典（默认 dict/shiro_aes_keys.txt）")
    ap.add_argument("--shiro-max-keys", type=int, default=40, help="L2 最多试几把钥")
    args = ap.parse_args()
    if args.stack.strip().lower() == "all":
        stacks = list(ALL_STACKS)
    else:
        stacks = [s.strip().lower() for s in args.stack.split(",") if s.strip()]
        bad = [s for s in stacks if s not in ALL_STACKS]
        if bad:
            print(f"[!] unknown stack: {bad}", file=sys.stderr)
            sys.exit(1)
    run(
        args.url, stacks, args.case, args.out,
        shiro_key_check=not args.no_shiro_keys,
        shiro_keys_file=args.shiro_keys,
        shiro_max_keys=args.shiro_max_keys,
    )


if __name__ == "__main__":
    main()
