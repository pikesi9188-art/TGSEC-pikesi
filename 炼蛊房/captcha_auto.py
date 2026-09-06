#!/usr/bin/env python3
"""验证码自动化（授权范围内）：字母图 OCR / 极验有头滑块 / 打码平台 token。

没有打码 Key 时：本机 Playwright 有头 + 真鼠标滑极验（不要 headless）。
有 CAPSOLVER_API_KEY / YESCAPTCHA_KEY / TWOCAPTCHA_KEY 时：纯 API 换 token。
Key 也可放 config/captcha_keys.env（已 gitignore）。

示例:
  python3 炼蛊房/captcha_auto.py doctor
  python3 炼蛊房/captcha_auto.py detect --url https://授权站/login --case <案卷>
  python3 炼蛊房/captcha_auto.py solve  --url https://授权站/login --case <案卷>
"""
from __future__ import annotations

import argparse
import json
import os
import random
import re
import shutil
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

OPS = Path(__file__).resolve().parent
ENGINE = (OPS.parent if (OPS.parent / "杀招").is_dir() else OPS.parents[1])
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))

from scope_lib import host_of, in_scope  # noqa: E402

UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
STEALTH = "Object.defineProperty(navigator,'webdriver',{get:()=>undefined})"

GEETEST_NEEDLES = (
    "initgeetest", "geetest.com", "gcaptcha4", "geetest_canvas",
    "geevisit.com", "geetest_slider",
    "vccgeetest.com", "gsensebot.com", "geetest_captcha_id",
    "force_geetest", "getgeecaptcha", "gcaptcha4-hrc",
)
CDN_RE = re.compile(
    r"([a-z0-9.-]+\.(?:geetest|geevisit|gsensebot|vccgeetest|botion)\.com)", re.I
)
NESTED_GEE_RE = re.compile(r'"geetest_captcha_id"\s*:\s*\{([^}]{0,800})\}', re.I)
HEX32_RE = re.compile(r"\b([0-9a-fA-F]{32})\b")
API_PROBE_PATHS = (
    "/user-api/captcha/getGeeCaptcha",
    "/api/captcha/getGeeCaptcha",
    "/hall/api/gohal/getSysInfo",
    "/hall/api/member/getSysInfo",
    "/common-api/common/getCommonSetting",
)
SNIFF_HOSTS = (
    "geetest", "gcaptcha4", "geevisit", "gsensebot", "vccgeetest",
    "botion", "getgeecaptcha",
)
RECAPTCHA_NEEDLES = ("grecaptcha", "recaptcha/api", "www.google.com/recaptcha", "g-recaptcha")
TURNSTILE_NEEDLES = ("challenges.cloudflare.com", "cf-turnstile", "cf_turnstile")
IMAGE_NEEDLES = ("/captcha", "captcha.php", "speccaptcha", "kaptcha", "verifycode")

CAPTCHA_ID_RE = re.compile(
    r"""["']?(?:captcha[_-]?id|captchaId)["']?\s*[=:]\s*['"]([0-9a-fA-F]{32})['"]""", re.I
)
GT_RE = re.compile(r"""["']?(?:\bgt|gee_id)["']?\s*[=:]\s*['"]([0-9a-fA-F]{32})['"]""", re.I)
CHALLENGE_RE = re.compile(r"""\bchallenge\s*[=:]\s*['"]([0-9a-fA-F]{8,64})['"]""", re.I)
SITEKEY_RE = re.compile(
    r"""(?:data-sitekey|sitekey|site_key)\s*[=:]\s*['"]([0-9A-Za-z_-]{20,100})['"]""", re.I
)
IMG_RE = re.compile(
    r"""(?:src|url)\s*[=:]\s*['"]([^'"]*(?:captcha|verifycode|kaptcha|vcode)[^'"]*)['"]""", re.I
)



def _ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def case_dir(case: str) -> Path:
    d = ENGINE / "案卷" / case / "测绘" / "captcha_auto"
    d.mkdir(parents=True, exist_ok=True)
    return d


def session_dir(case: str) -> Path:
    d = ENGINE / "案卷" / case / "接管" / "session"
    d.mkdir(parents=True, exist_ok=True)
    return d


def save(case: str, name: str, obj: Any) -> Path:
    p = case_dir(case) / name
    p.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return p


def ensure_url_scope(url: str) -> str:
    h = host_of(url)
    if not h:
        raise SystemExit("[scope] 无法解析 host")
    if h in ("127.0.0.1", "localhost", "::1"):
        return h
    if not in_scope(h):
        raise SystemExit(f"[scope] {h} 不在授权范围，拒绝请求")
    return h


def load_key_files() -> None:
    for p in (ENGINE / "config" / "captcha_keys.env", ENGINE / ".env"):
        if not p.is_file():
            continue
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            s = line.strip()
            if not s or s.startswith("#") or "=" not in s:
                continue
            k, v = s.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def env_key(*names: str) -> str:
    load_key_files()
    for n in names:
        v = (os.environ.get(n) or "").strip()
        if v:
            return v
    return ""


def extract_ids(text: str) -> dict[str, Any]:
    raw = text or ""
    ids: dict[str, Any] = {
        "captcha_id": (CAPTCHA_ID_RE.findall(raw) or [""])[0],
        "gt": (GT_RE.findall(raw) or [""])[0],
        "challenge": (CHALLENGE_RE.findall(raw) or [""])[0],
        "sitekey": (SITEKEY_RE.findall(raw) or [""])[0],
        "image_urls": list(dict.fromkeys(IMG_RE.findall(raw)[:8])),
        "custom_servers": list(dict.fromkeys(CDN_RE.findall(raw))),
        "api_subdomain": "",
        "ids_by_scene": {},
    }
    m = re.search(r'"clientServer"\s*:\s*"([^"]+)"', raw)
    if m:
        ids["api_subdomain"] = normalize_subdomain(m.group(1))
    nested = NESTED_GEE_RE.search(raw)
    if nested:
        block = nested.group(1)
        scenes = dict(re.findall(r'"(login|register|recharge|feedback|force_geetest)"\s*:\s*"([0-9a-fA-F]{32})"', block, re.I))
        ids["ids_by_scene"] = scenes
        if not ids["captcha_id"]:
            ids["captcha_id"] = scenes.get("login") or scenes.get("force_geetest") or (HEX32_RE.findall(block) or [""])[0]
    if not ids["captcha_id"]:
        fm = re.search(r'"force_geetest"\s*:\s*"([0-9a-fA-F]{32})"', raw, re.I)
        if fm:
            ids["captcha_id"] = fm.group(1)
    if not ids["captcha_id"] and ids["gt"]:
        ids["captcha_id"] = ids["gt"]
    if not ids["api_subdomain"] and ids["custom_servers"]:
        # 优先业务 load 域，不是 static
        dyn = [h for h in ids["custom_servers"] if "static" not in h.lower()]
        ids["api_subdomain"] = normalize_subdomain((dyn or ids["custom_servers"])[0])
    return ids


def normalize_subdomain(host: str) -> str:
    h = (host or "").strip()
    h = re.sub(r"^https?://", "", h, flags=re.I)
    h = h.split("/")[0].split("?")[0]
    return h.lower()


def classify_html(text: str) -> dict[str, Any]:
    low = (text or "").lower()
    pulled = extract_ids(text or "")
    kinds: list[str] = []
    if any(n in low for n in GEETEST_NEEDLES) or CAPTCHA_ID_RE.search(text or "") or pulled.get("ids_by_scene"):
        kinds.append("geetest")
    if any(n in low for n in RECAPTCHA_NEEDLES) or (pulled.get("sitekey") or "").startswith("6L"):
        kinds.append("recaptcha")
    if any(n in low for n in TURNSTILE_NEEDLES):
        kinds.append("turnstile")
    if any(n in low for n in IMAGE_NEEDLES):
        kinds.append("image")
    version = ""
    if "geetest" in kinds:
        v4 = (
            "gcaptcha4" in low or "lot_number" in low or "vccgeetest" in low
            or bool(pulled.get("captcha_id")) or bool(pulled.get("ids_by_scene"))
            or CAPTCHA_ID_RE.search(text or "")
        )
        version = "v4" if v4 else "v3"
    out = {"kinds": kinds or ["unknown"], "geetest_version": version, "len": len(text or "")}
    out.update(pulled)
    return out


def human_track(distance: float, steps: int | None = None) -> list[tuple[float, float, float]]:
    n = steps or random.randint(28, 42)
    out: list[tuple[float, float, float]] = []
    for i in range(n):
        t = (i + 1) / n
        ease = 2 * t * t if t < 0.5 else 1 - ((-2 * t + 2) ** 2) / 2
        out.append((distance * ease, random.uniform(-2.2, 2.2), random.uniform(0.008, 0.022)))
    out.append((distance + random.uniform(2.0, 6.0), random.uniform(-1, 1), 0.05))
    out.append((distance, 0.0, 0.08))
    return out


def gap_from_columns(col_score: list[float], skip: int = 40) -> int:
    if not col_score:
        return 0
    best_i, best_s = skip, -1.0
    end = max(skip + 1, len(col_score) - 20)
    for i in range(skip, end):
        if col_score[i] > best_s:
            best_s = col_score[i]
            best_i = i
    return best_i


def gap_from_png(data: bytes) -> dict[str, Any]:
    try:
        from PIL import Image
        import io
    except ImportError:
        return {"ok": False, "reason": "no_pillow"}
    im = Image.open(io.BytesIO(data)).convert("RGB")
    w, h = im.size
    pix = im.load()
    scores: list[float] = []
    for x in range(max(0, w - 1)):
        s = 0
        for y in range(h):
            a, b = pix[x, y], pix[x + 1, y]
            s += abs(a[0] - b[0]) + abs(a[1] - b[1]) + abs(a[2] - b[2])
        scores.append(float(s))
    g = gap_from_columns(scores, skip=max(20, w // 8))
    return {"ok": True, "gapPx": g, "w": w, "h": h}


def _as_dict(obj: Any) -> dict[str, Any] | None:
    if isinstance(obj, dict):
        inner = obj.get("data")
        if isinstance(inner, dict) and not interesting_token(obj) and (
            interesting_token(inner) or inner.get("captchaId") or inner.get("clientServer")
        ):
            return inner
        return obj
    if isinstance(obj, list) and obj and isinstance(obj[0], dict):
        return obj[0]
    return None


def parse_geetest_body(body: str) -> dict[str, Any] | None:
    raw = (body or "").strip()
    if not raw:
        return None
    if raw[0] in "{[":
        try:
            return _as_dict(json.loads(raw))
        except Exception:
            return None
    m = re.search(r"\((\{.*\})\)\s*;?\s*$", raw, re.S)
    if not m:
        return None
    try:
        return _as_dict(json.loads(m.group(1)))
    except Exception:
        return None


def interesting_token(obj: dict[str, Any] | None) -> bool:
    if not obj:
        return False
    keys = {str(k).lower() for k in obj}
    return bool(keys & {
        "lot_number", "pass_token", "captcha_output",
        "geetest_validate", "geetest_seccode",
    })


def http_json(url: str, payload: dict[str, Any], timeout: float = 30) -> dict[str, Any]:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": UA},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl.create_default_context()) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace") or "{}")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        try:
            return json.loads(body) if body else {"error": str(e), "status": e.code}
        except Exception:
            return {"error": str(e), "status": e.code, "body": body[:300]}


def fetch_bytes(url: str, insecure: bool = False, timeout: float = 20) -> bytes:
    ctx = ssl._create_unverified_context() if insecure else ssl.create_default_context()
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        return resp.read(2_000_000)


def fetch_text(url: str, insecure: bool = False, timeout: float = 20) -> str:
    return fetch_bytes(url, insecure=insecure, timeout=timeout).decode("utf-8", errors="replace")


def solver_keys() -> dict[str, str]:
    return {
        "ezcaptcha": env_key("EZCAPTCHA_KEY", "EZCAPTCHA_API_KEY"),
        "capsolver": env_key("CAPSOLVER_API_KEY", "CAPSOLVER_KEY"),
        "yescaptcha": env_key("YESCAPTCHA_KEY", "YESCAPTCHA_API_KEY"),
        "twocaptcha": env_key("TWOCAPTCHA_KEY", "TWO_CAPTCHA_API_KEY", "TWOCAPTCHA_API_KEY"),
    }


def poll_caplike(base: str, key: str, task: dict[str, Any], timeout: int = 120) -> dict[str, Any]:
    created = http_json(f"{base}/createTask", {"clientKey": key, "task": task})
    tid = created.get("taskId")
    if not tid:
        return {"ok": False, "error": created}
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = http_json(f"{base}/getTaskResult", {"clientKey": key, "taskId": tid})
        st = (r.get("status") or "").lower()
        if st == "ready":
            return {"ok": True, "solution": r.get("solution") or r, "raw": r}
        if r.get("errorId") not in (None, 0) and st not in ("processing", "idle", ""):
            return {"ok": False, "error": r}
        time.sleep(3)
    return {"ok": False, "error": "poll_timeout", "taskId": tid}


def solve_token_api(
    website: str,
    *,
    kind: str = "geetest",
    captcha_id: str = "",
    gt: str = "",
    challenge: str = "",
    sitekey: str = "",
    version: int = 4,
    api_subdomain: str = "",
) -> dict[str, Any]:
    keys = solver_keys()
    kind = (kind or "geetest").lower()
    if kind == "geetest":
        cid = captcha_id or gt
        if not cid:
            return {"ok": False, "error": "需要 captcha-id / gt（detect 会自动抽）"}
        if keys["ezcaptcha"]:
            task: dict[str, Any] = {
                "type": "GeeTestTaskProxyLess",
                "websiteURL": website,
                "version": version,
                "gt": cid,
                "captchaId": cid,
            }
            if version == 4:
                task["initParameters"] = {"captcha_id": cid}
            if challenge:
                task["challenge"] = challenge
            if api_subdomain:
                task["geetestApiServerSubdomain"] = api_subdomain
            r = poll_caplike("https://api.ez-captcha.com", keys["ezcaptcha"], task)
            r["provider"] = "ezcaptcha"
            return r
        if keys["capsolver"]:
            task: dict[str, Any] = {
                "type": "GeeTestTaskProxyLess",
                "websiteURL": website,
                "version": version,
                "gt": cid,
                "captchaId": cid,
            }
            if version == 4:
                task["initParameters"] = {"captcha_id": cid}
            if challenge:
                task["challenge"] = challenge
            if api_subdomain:
                task["geetestApiServerSubdomain"] = api_subdomain
            r = poll_caplike("https://api.capsolver.com", keys["capsolver"], task)
            r["provider"] = "capsolver"
            return r
        if keys["yescaptcha"]:
            task = {
                "type": "GeeTestTaskProxyless",
                "websiteURL": website,
                "gt": cid,
                "version": str(version),
            }
            if version == 4:
                task["initParameters"] = {"captcha_id": cid}
            if challenge:
                task["challenge"] = challenge
            if api_subdomain:
                task["geetestApiServerSubdomain"] = api_subdomain
            r = poll_caplike("https://api.yescaptcha.com", keys["yescaptcha"], task)
            r["provider"] = "yescaptcha"
            return r
        if keys["twocaptcha"]:
            return solve_twocaptcha(
                keys["twocaptcha"], "geetest", website, cid, challenge, version, "", api_subdomain,
            )
    if kind == "recaptcha":
        sk = sitekey or captcha_id
        if not sk:
            return {"ok": False, "error": "需要 recaptcha sitekey"}
        if keys["ezcaptcha"]:
            r = poll_caplike("https://api.ez-captcha.com", keys["ezcaptcha"], {
                "type": "ReCaptchaV2TaskProxyLess",
                "websiteURL": website,
                "websiteKey": sk,
            })
            r["provider"] = "ezcaptcha"
            return r
        if keys["capsolver"]:
            r = poll_caplike("https://api.capsolver.com", keys["capsolver"], {
                "type": "ReCaptchaV2TaskProxyLess",
                "websiteURL": website,
                "websiteKey": sk,
            })
            r["provider"] = "capsolver"
            return r
        if keys["yescaptcha"]:
            r = poll_caplike("https://api.yescaptcha.com", keys["yescaptcha"], {
                "type": "NoCaptchaTaskProxyless",
                "websiteURL": website,
                "websiteKey": sk,
            })
            r["provider"] = "yescaptcha"
            return r
        if keys["twocaptcha"]:
            return solve_twocaptcha(keys["twocaptcha"], "recaptcha", website, "", "", 0, sk)
    if kind == "turnstile":
        sk = sitekey or captcha_id
        if not sk:
            return {"ok": False, "error": "需要 turnstile sitekey"}
        if keys["ezcaptcha"]:
            r = poll_caplike("https://api.ez-captcha.com", keys["ezcaptcha"], {
                "type": "AntiTurnstileTaskProxyLess",
                "websiteURL": website,
                "websiteKey": sk,
            })
            r["provider"] = "ezcaptcha"
            return r
        if keys["capsolver"]:
            r = poll_caplike("https://api.capsolver.com", keys["capsolver"], {
                "type": "AntiTurnstileTaskProxyLess",
                "websiteURL": website,
                "websiteKey": sk,
            })
            r["provider"] = "capsolver"
            return r
        if keys["yescaptcha"]:
            r = poll_caplike("https://api.yescaptcha.com", keys["yescaptcha"], {
                "type": "TurnstileTaskProxyless",
                "websiteURL": website,
                "websiteKey": sk,
            })
            r["provider"] = "yescaptcha"
            return r
        if keys["twocaptcha"]:
            return solve_twocaptcha(keys["twocaptcha"], "turnstile", website, "", "", 0, sk)
    return {
        "ok": False,
        "error": "no_solver_key",
        "hint": "export CAPSOLVER_API_KEY=… 或写入 config/captcha_keys.env",
    }


def solve_twocaptcha(
    key: str, kind: str, website: str, captcha_id: str, challenge: str, version: int, sitekey: str,
    api_subdomain: str = "",
) -> dict[str, Any]:
    q: dict[str, str] = {"key": key, "pageurl": website, "json": "1"}
    if kind == "geetest":
        q["method"] = "geetest_v4" if version == 4 else "geetest"
        if version == 4:
            q["captcha_id"] = captcha_id
        else:
            q["gt"] = captcha_id
            if challenge:
                q["challenge"] = challenge
        if api_subdomain:
            q["api_server"] = api_subdomain
    elif kind == "recaptcha":
        q["method"] = "userrecaptcha"
        q["googlekey"] = sitekey
    else:
        q["method"] = "turnstile"
        q["sitekey"] = sitekey
    url = "https://2captcha.com/in.php?" + urllib.parse.urlencode(q)
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=30, context=_ssl_ctx()) as resp:
            create = json.loads(resp.read().decode() or "{}")
    except Exception as e:
        return {"ok": False, "provider": "twocaptcha", "error": str(e)}
    rid = create.get("request")
    if create.get("status") != 1 or not rid:
        return {"ok": False, "provider": "twocaptcha", "error": create}
    deadline = time.time() + 120
    while time.time() < deadline:
        time.sleep(5)
        res_url = "https://2captcha.com/res.php?" + urllib.parse.urlencode(
            {"key": key, "action": "get", "id": rid, "json": 1}
        )
        req = urllib.request.Request(res_url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=30, context=_ssl_ctx()) as resp:
            got = json.loads(resp.read().decode() or "{}")
        if got.get("status") == 1:
            return {"ok": True, "provider": "twocaptcha", "solution": got.get("request")}
        if got.get("request") not in ("CAPCHA_NOT_READY", "CAPTCHA_NOT_READY"):
            return {"ok": False, "provider": "twocaptcha", "error": got}
    return {"ok": False, "provider": "twocaptcha", "error": "poll_timeout"}


def resolve_proxy_arg(raw: str) -> str:
    """空 / pool / auto → 从仓库代理池取一条 HTTP。禁止为此去 SSH 用户主机。"""
    s = (raw or "").strip()
    if not s or s.lower() in ("pool", "auto"):
        sys.path.insert(0, str(ENGINE))
        from engine.proxy_pool import pick_proxy_url
        url = pick_proxy_url(http_only=True, probe=True, probe_limit=8)
        if not url:
            raise SystemExit("[err] 代理池没有可用 HTTP 节点，见 传承/狼烟.md")
        return url
    return s


def playwright_proxy(raw: str) -> dict[str, str] | None:
    """Playwright 不能把 user:pass 塞进 server；SOCKS5 带认证会直接失败。"""
    if not raw:
        return None
    sys.path.insert(0, str(ENGINE))
    from engine.proxy_pool import to_playwright
    cfg = to_playwright(raw)
    scheme = (cfg.get("server") or "").split("://", 1)[0].lower()
    if scheme.startswith("socks") and cfg.get("username"):
        raise SystemExit(
            "[err] Chromium 不支持带认证的 SOCKS5。改用 "
            "`python3 main.py proxy pick --http --probe --url-only` 或 --proxy pool"
        )
    return cfg


def launch_browser(headless: bool, proxy: str = ""):
    from playwright.sync_api import sync_playwright

    pw = sync_playwright().start()
    args = ["--disable-blink-features=AutomationControlled", "--disable-dev-shm-usage"]
    kwargs: dict[str, Any] = {"headless": headless, "args": args}
    if proxy:
        url = resolve_proxy_arg(proxy)
        cfg = playwright_proxy(url)
        if cfg:
            kwargs["proxy"] = cfg
            print(f"[proxy] {cfg.get('server')}", flush=True)
    browser = pw.chromium.launch(**kwargs)
    ctx = browser.new_context(locale="zh-CN", user_agent=UA, viewport={"width": 1280, "height": 800})
    ctx.add_init_script(STEALTH)
    return pw, browser, ctx, ctx.new_page()


def sync_session(case: str, ctx, storage: Path) -> Path:
    dest = session_dir(case)
    shutil.copy2(storage, dest / "storage_state.json")
    cookies = ctx.cookies()
    (dest / "cookies.json").write_text(
        json.dumps(cookies, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return dest


GAP_JS = """
() => {
  const bg = document.querySelector('.geetest_canvas_bg, canvas.geetest_canvas_bg, canvas.geetest_slice_bg');
  const full = document.querySelector('.geetest_canvas_fullbg, canvas.geetest_canvas_fullbg');
  const btn = document.querySelector('.geetest_slider_button, .geetest_btn, .geetest_arrow, .geetest_slider .geetest_btn');
  if (!bg) return {ok:false, reason:'no_bg'};
  const w = bg.width || Math.round(bg.getBoundingClientRect().width);
  const h = bg.height || Math.round(bg.getBoundingClientRect().height);
  let img, fullData = null;
  try { img = bg.getContext('2d').getImageData(0,0,w,h).data; }
  catch (e) { return {ok:false, reason:'canvas_taint', hasBtn: !!btn}; }
  if (full) {
    try { fullData = full.getContext('2d').getImageData(0,0,full.width||w,full.height||h).data; }
    catch (e) { fullData = null; }
  }
  const col = [];
  for (let x = 0; x < w; x++) {
    let s = 0;
    for (let y = 0; y < h; y++) {
      const i = (y * w + x) * 4;
      if (fullData) {
        s += Math.abs(img[i]-fullData[i]) + Math.abs(img[i+1]-fullData[i+1]) + Math.abs(img[i+2]-fullData[i+2]);
      } else {
        const j = (y * w + Math.min(x+1, w-1)) * 4;
        s += Math.abs(img[i]-img[j]) + Math.abs(img[i+1]-img[j+1]) + Math.abs(img[i+2]-img[j+2]);
      }
    }
    col.push(s);
  }
  let best = 40, bestS = -1;
  for (let x = 40; x < w - 20; x++) {
    if (col[x] > bestS) { bestS = col[x]; best = x; }
  }
  const bgr = bg.getBoundingClientRect();
  const scale = w ? (bgr.width / w) : 1;
  const br = btn ? btn.getBoundingClientRect() : null;
  return {
    ok: true, gapPx: best, scale, distance: best * scale,
    btn: br ? {x: br.x, y: br.y, w: br.width, h: br.height} : null,
  };
}
"""

EXTRACT_JS = """
() => {
  const html = document.documentElement ? document.documentElement.outerHTML : '';
  const scripts = [...document.scripts].map(s => (s.src||'') + '\\n' + (s.textContent||'')).join('\\n');
  return html + '\\n' + scripts;
}
"""


def page_state(page) -> str:
    try:
        return page.evaluate(
            """() => {
              const el = document.querySelector('.geetest_slider, .geetest_panel, .geetest_radar_tip, .geetest_success_radar_tip');
              const cls = el ? el.className : '';
              const t = document.body ? document.body.innerText.slice(0, 400) : '';
              return cls + '|' + t;
            }"""
        )
    except Exception:
        return ""


def click_if(page, selector: str) -> bool:
    loc = page.locator(selector).first
    try:
        if loc.count() and loc.is_visible():
            loc.click(timeout=2000)
            return True
    except Exception:
        return False
    return False


def ensure_widget(page, click: str = "") -> None:
    if click:
        click_if(page, click)
        page.wait_for_timeout(800)
    for sel in (".geetest_radar_tip", ".geetest_btn_click", ".geetest_wait"):
        if click_if(page, sel):
            page.wait_for_timeout(1200)
            break
    try:
        page.wait_for_selector(
            ".geetest_slider_button, .geetest_canvas_bg, canvas.geetest_canvas_bg, .geetest_arrow",
            timeout=8000,
        )
    except Exception:
        pass


def screenshot_gap(page) -> dict[str, Any]:
    for sel in (".geetest_canvas_bg", "canvas.geetest_canvas_bg", ".geetest_window", ".geetest_panel_next"):
        loc = page.locator(sel).first
        try:
            if loc.count() and loc.is_visible():
                data = loc.screenshot()
                info = gap_from_png(data)
                btn = page.locator(".geetest_slider_button, .geetest_arrow, .geetest_btn").first
                box = btn.bounding_box() if btn.count() else None
                if info.get("ok") and box:
                    css_w = loc.bounding_box() or {}
                    scale = (css_w.get("width") or info.get("w") or 1) / max(int(info.get("w") or 1), 1)
                    info["distance"] = float(info["gapPx"]) * float(scale)
                    info["scale"] = scale
                    info["btn"] = {"x": box["x"], "y": box["y"], "w": box["width"], "h": box["height"]}
                    info["via"] = "screenshot"
                    return info
        except Exception:
            continue
    return {"ok": False, "reason": "no_screenshot"}


def do_slide(page, retries: int = 4, click: str = "") -> dict[str, Any]:
    last: dict[str, Any] = {"ok": False}
    ensure_widget(page, click)
    for attempt in range(1, retries + 1):
        page.wait_for_timeout(600)
        info = page.evaluate(GAP_JS)
        if not info or not info.get("ok") or not info.get("btn"):
            info = screenshot_gap(page)
        last = {"attempt": attempt, **(info or {})}
        if not info or not info.get("btn"):
            click_if(page, ".geetest_refresh, .geetest_refresh_1")
            page.wait_for_timeout(1000)
            continue
        btn = info["btn"]
        sx = btn["x"] + btn["w"] / 2
        sy = btn["y"] + btn["h"] / 2
        dist = float(info.get("distance") or 0)
        page.mouse.move(sx, sy)
        page.wait_for_timeout(int(random.uniform(200, 400)))
        page.mouse.down()
        for dx, dy, slp in human_track(dist):
            page.mouse.move(sx + dx, sy + dy)
            time.sleep(slp)
        page.mouse.up()
        page.wait_for_timeout(1500)
        st = page_state(page)
        last["state"] = st
        if "geetest_success" in st or "验证成功" in st:
            last["ok"] = True
            last["result"] = "success"
            return last
        if "geetest_fail" in st or "请再试" in st:
            last["result"] = "fail_position"
            click_if(page, ".geetest_refresh, .geetest_refresh_1")
            continue
        last["result"] = "unknown"
    last["ok"] = False
    return last


def attach_sniffer(page, bag: dict[str, Any]) -> None:
    bag.setdefault("tokens", [])
    bag.setdefault("ids", {})

    def on_response(resp) -> None:
        u = resp.url
        low = u.lower()
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(u).query)
        for key in ("captcha_id", "captchaId", "gt"):
            if qs.get(key):
                bag["ids"][key] = qs[key][0]
        if not any(x in low for x in SNIFF_HOSTS):
            return
        try:
            body = resp.text()
        except Exception:
            return
        obj = parse_geetest_body(body)
        if interesting_token(obj):
            bag["tokens"].append({"url": u, "status": resp.status, "json": obj})
        elif obj:
            pulled = extract_ids(json.dumps(obj, ensure_ascii=False))
            for k in ("captcha_id", "gt", "challenge", "api_subdomain"):
                if pulled.get(k) and not bag["ids"].get(k):
                    bag["ids"][k] = pulled[k]

    page.on("response", on_response)


def cmd_doctor(_args: argparse.Namespace) -> int:
    keys = solver_keys()
    out: dict[str, Any] = {
        "ts": _now(),
        "keys": {k: bool(v) for k, v in keys.items()},
        "key_file": (ENGINE / "config" / "captcha_keys.env").is_file(),
    }
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
        out["playwright"] = True
    except Exception as e:
        out["playwright"] = False
        out["playwright_err"] = str(e)
    try:
        import ddddocr  # noqa: F401
        out["ddddocr"] = True
    except Exception:
        out["ddddocr"] = False
    try:
        from PIL import Image  # noqa: F401
        out["pillow"] = True
    except Exception:
        out["pillow"] = False
    print(json.dumps(out, ensure_ascii=False, indent=2))
    if out["playwright"]:
        print("[+] 有头滑块: captcha_auto.py slide --url … --case …")
    else:
        print("[!] pip3 install playwright && python3 -m playwright install chromium")
    if any(keys.values()):
        print("[+] 已有打码 Key → token/solve 可无界面")
        active = [p for p, v in keys.items() if v]
        print(f"    激活: {', '.join(active)}")
    else:
        print("[!] 无 Key。复制 config/captcha_keys.env.example → captcha_keys.env")
        print("    或 export EZCAPTCHA_KEY=… / CAPSOLVER_API_KEY=… / YESCAPTCHA_KEY=…")
    if not out["ddddocr"]:
        print("[!] 字母图: bash tools/captcha-ocr/install.sh")
    return 0 if out["playwright"] or any(keys.values()) or out["ddddocr"] else 2


def _fetch_api(url: str, insecure: bool) -> str:
    try:
        return fetch_text(url, insecure=insecure, timeout=8)
    except Exception:
        data = json.dumps({}).encode()
        ctx = ssl._create_unverified_context() if insecure else ssl.create_default_context()
        req = urllib.request.Request(
            url, data=data, method="POST",
            headers={"User-Agent": UA, "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
            return resp.read(400_000).decode("utf-8", errors="replace")


def probe_apis(page_url: str, insecure: bool = True) -> list[dict[str, Any]]:
    parsed = urllib.parse.urlparse(page_url)
    origin = f"{parsed.scheme or 'https'}://{parsed.netloc}"
    hits: list[dict[str, Any]] = []
    for path in API_PROBE_PATHS:
        url = origin + path
        try:
            raw = _fetch_api(url, insecure)
        except Exception as e:
            hits.append({"path": path, "ok": False, "error": str(e)[:120]})
            continue
        info = extract_ids(raw)
        useful = bool(info.get("captcha_id") or info.get("gt") or info.get("custom_servers"))
        hits.append({
            "path": path,
            "ok": useful,
            "status_len": len(raw),
            "captcha_id": info.get("captcha_id") or "",
            "api_subdomain": info.get("api_subdomain") or "",
            "ids_by_scene": info.get("ids_by_scene") or {},
        })
    return hits


def _detect_payload(args: argparse.Namespace) -> dict[str, Any]:
    html = ""
    via = "http"
    if args.browser:
        pw, browser, ctx, page = launch_browser(args.headless, args.proxy)
        bag: dict[str, Any] = {}
        attach_sniffer(page, bag)
        try:
            page.goto(args.url, wait_until="domcontentloaded", timeout=args.timeout_ms)
            page.wait_for_timeout(4000)
            html = page.evaluate(EXTRACT_JS)
            via = "playwright"
        finally:
            browser.close()
            pw.stop()
        info = classify_html(html)
        info["ids_from_net"] = bag.get("ids") or {}
        if bag.get("ids", {}).get("captcha_id") and not info.get("captcha_id"):
            info["captcha_id"] = bag["ids"]["captcha_id"]
        if bag.get("ids", {}).get("gt") and not info.get("gt"):
            info["gt"] = bag["ids"]["gt"]
        if bag.get("ids", {}).get("api_subdomain") and not info.get("api_subdomain"):
            info["api_subdomain"] = bag["ids"]["api_subdomain"]
    else:
        html = fetch_text(args.url, insecure=getattr(args, "insecure", False))
        info = classify_html(html)
    if getattr(args, "probe_api", False):
        info["api_probes"] = probe_apis(args.url, insecure=True)
        for hit in info["api_probes"]:
            if not hit.get("ok"):
                continue
            if hit.get("captcha_id") and not info.get("captcha_id"):
                info["captcha_id"] = hit["captcha_id"]
                info["geetest_version"] = info.get("geetest_version") or "v4"
                if "geetest" not in info["kinds"]:
                    info["kinds"] = ["geetest"] + [k for k in info["kinds"] if k != "unknown"]
            if hit.get("api_subdomain") and not info.get("api_subdomain"):
                info["api_subdomain"] = hit["api_subdomain"]
            if hit.get("ids_by_scene") and not info.get("ids_by_scene"):
                info["ids_by_scene"] = hit["ids_by_scene"]
    info.update({"ts": _now(), "url": args.url, "via": via})
    return info


def cmd_detect(args: argparse.Namespace) -> int:
    ensure_url_scope(args.url)
    try:
        info = _detect_payload(args)
    except Exception as e:
        raise SystemExit(f"[err] 探测失败: {e}；JS 页请加 --browser")
    p = save(args.case, "detect.json", info)
    print(
        f"[+] kinds={info['kinds']} geetest={info.get('geetest_version') or '-'} "
        f"id={info.get('captcha_id') or info.get('gt') or '-'} "
        f"cdn={info.get('api_subdomain') or '-'} via={info.get('via')} → {p}"
    )
    kinds = info["kinds"]
    if "geetest" in kinds:
        print("  next: captcha_auto.py solve --url … --case …")
    elif "image" in kinds:
        print("  next: captcha_auto.py ocr --url … --case …")
    elif "turnstile" in kinds or "recaptcha" in kinds:
        print("  next: 有 Key 则 token --kind turnstile|recaptcha --sitekey …；否则 cf_session capture")
    return 0


def cmd_slide(args: argparse.Namespace) -> int:
    ensure_url_scope(args.url)
    bag: dict[str, Any] = {}
    pw, browser, ctx, page = launch_browser(args.headless, args.proxy)
    attach_sniffer(page, bag)
    try:
        page.goto(args.url, wait_until="domcontentloaded", timeout=args.timeout_ms)
        page.wait_for_timeout(2500)
        result = do_slide(page, retries=args.retries, click=args.click)
        storage = case_dir(args.case) / "storage_state.json"
        ctx.storage_state(path=str(storage))
        sess = sync_session(args.case, ctx, storage)
        out = {
            "ts": _now(),
            "url": args.url,
            "slide": result,
            "tokens": bag.get("tokens") or [],
            "ids": bag.get("ids") or {},
            "cookie_names": [c.get("name") for c in ctx.cookies()],
            "storage_state": str(storage),
            "session_dir": str(sess),
            "headless": args.headless,
            "next": [
                f"python3 炼蛊房/cf_session.py consume --url {args.url} --case {args.case}",
                f"python3 炼蛊房/session_pipeline.py --domain {host_of(args.url)} --case {args.case} --skip-probe",
            ],
        }
        p = save(args.case, "slide.json", out)
        print(f"[{'OK' if result.get('ok') else 'FAIL'}] slide={result.get('result')} → {p}")
        print(f"  session → {sess}")
        if bag.get("tokens"):
            print(f"  captured {len(bag['tokens'])} geetest token(s)")
        if not result.get("ok"):
            print("  未过：--click 触发按钮，或 config/captcha_keys.env 走 token")
            return 2
        return 0
    finally:
        browser.close()
        pw.stop()


def cmd_token(args: argparse.Namespace) -> int:
    ensure_url_scope(args.url)
    det_path = case_dir(args.case) / "detect.json"
    det: dict[str, Any] = {}
    if det_path.is_file():
        try:
            det = json.loads(det_path.read_text(encoding="utf-8"))
        except Exception:
            det = {}
    kind = args.kind
    if kind == "auto":
        kinds = det.get("kinds") or []
        kind = "recaptcha" if "recaptcha" in kinds else "turnstile" if "turnstile" in kinds else "geetest"
    r = solve_token_api(
        args.url,
        kind=kind,
        captcha_id=args.captcha_id or det.get("captcha_id") or "",
        gt=args.gt or det.get("gt") or "",
        challenge=args.challenge or det.get("challenge") or "",
        sitekey=args.sitekey or det.get("sitekey") or "",
        version=args.version if args.version else (
            3 if det.get("geetest_version") == "v3" else 4
        ),
        api_subdomain=getattr(args, "api_subdomain", "") or det.get("api_subdomain") or "",
    )
    p = save(args.case, "token.json", {"ts": _now(), "url": args.url, "kind": kind, **r})
    print(f"[{'OK' if r.get('ok') else 'FAIL'}] kind={kind} → {p}")
    if r.get("ok"):
        print(json.dumps(r.get("solution"), ensure_ascii=False)[:500])
    else:
        print(r.get("error") or r.get("hint") or r)
    return 0 if r.get("ok") else 2


def cmd_ocr(args: argparse.Namespace) -> int:
    ensure_url_scope(args.url)
    ocr_dir = ENGINE / "tools" / "captcha-ocr"
    if str(ocr_dir) not in sys.path:
        sys.path.insert(0, str(ocr_dir))
    from ocr_solve import solve_bytes  # type: ignore

    img_url = args.image_url
    if not img_url:
        html = fetch_text(args.url, insecure=True)
        ids = extract_ids(html)
        cands = ids.get("image_urls") or []
        if not cands:
            raise SystemExit("页面没找到 captcha 图 URL，请 --image-url")
        img_url = urllib.parse.urljoin(args.url, cands[0])
    data = fetch_bytes(img_url, insecure=True)
    result = solve_bytes(data, beta=args.beta)
    result.update({"image_url": img_url, "page": args.url})
    p = save(args.case, "ocr.json", result)
    print(f"[{'OK' if result.get('ok') else 'FAIL'}] text={result.get('text')!r} → {p}")
    return 0 if result.get("ok") else 2


def cmd_solve(args: argparse.Namespace) -> int:
    ensure_url_scope(args.url)
    keys = solver_keys()
    d_args = argparse.Namespace(
        url=args.url, case=args.case, browser=False, headless=args.headless,
        proxy=args.proxy, timeout_ms=args.timeout_ms, insecure=True,
        probe_api=True,
    )
    try:
        info = classify_html(fetch_text(args.url, insecure=True))
        merged = {**info, "url": args.url, "via": "http"}
        for hit in probe_apis(args.url, insecure=True):
            if hit.get("ok") and hit.get("captcha_id") and not merged.get("captcha_id"):
                merged["captcha_id"] = hit["captcha_id"]
                merged["kinds"] = ["geetest"] + [k for k in merged["kinds"] if k != "unknown"]
                merged["geetest_version"] = "v4"
            if hit.get("api_subdomain") and not merged.get("api_subdomain"):
                merged["api_subdomain"] = hit["api_subdomain"]
            if hit.get("ids_by_scene") and not merged.get("ids_by_scene"):
                merged["ids_by_scene"] = hit["ids_by_scene"]
        info = merged
        if info["kinds"] == ["unknown"] and not info.get("captcha_id"):
            raise RuntimeError("html_unknown")
        save(args.case, "detect.json", {"ts": _now(), "url": args.url, "via": "http", **info})
        print(f"[+] kinds={info['kinds']} id={info.get('captcha_id') or info.get('gt') or '-'} via=http")
    except SystemExit:
        raise
    except Exception:
        d_args.browser = True
        cmd_detect(d_args)
    det = json.loads((case_dir(args.case) / "detect.json").read_text(encoding="utf-8"))
    kinds = det.get("kinds") or []
    if "image" in kinds and "geetest" not in kinds:
        args.image_url = args.image_url if hasattr(args, "image_url") else ""
        if not getattr(args, "image_url", ""):
            args.image_url = ""
        args.beta = getattr(args, "beta", False)
        return cmd_ocr(args)
    if "geetest" in kinds:
        cid = args.captcha_id or det.get("captcha_id") or det.get("gt") or ""
        if any(keys.values()) and cid:
            args.kind = "geetest"
            args.captcha_id = cid
            args.gt = args.gt or det.get("gt") or ""
            args.challenge = args.challenge or det.get("challenge") or ""
            args.sitekey = ""
            args.version = 3 if det.get("geetest_version") == "v3" else 4
            return cmd_token(args)
        if any(keys.values()) and not cid:
            print("[!] 有 Key 但页上没抽到 captchaId，改走滑块；或 --browser detect 再 token")
        return cmd_slide(args)
    if "turnstile" in kinds or "recaptcha" in kinds:
        kind = "recaptcha" if "recaptcha" in kinds else "turnstile"
        sk = args.sitekey or det.get("sitekey") or ""
        if any(keys.values()) and sk:
            args.kind = kind
            args.sitekey = sk
            return cmd_token(args)
        print(f"[*] {kind} 无 Key/sitekey → cf_session capture")
        print(f"    python3 炼蛊房/cf_session.py capture --url {args.url} --case {args.case}")
        return 0
    print("[*] 未识别。可强制 slide / token / ocr")
    return 1


def cmd_harvest(args: argparse.Namespace) -> int:
    root = Path(args.path)
    if not root.exists():
        raise SystemExit(f"找不到 {root}")
    suf = {".js", ".json", ".html", ".txt", ".md"}
    hits: list[dict[str, Any]] = []
    files = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in suf]
    for p in files[:4000]:
        try:
            if p.stat().st_size > 8_000_000:
                continue
            text = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        info = extract_ids(text)
        kinds = classify_html(text)["kinds"]
        if not (info.get("captcha_id") or info.get("gt") or info.get("custom_servers")):
            continue
        hits.append({
            "file": str(p),
            "captcha_id": info.get("captcha_id") or "",
            "gt": info.get("gt") or "",
            "api_subdomain": info.get("api_subdomain") or "",
            "custom_servers": info.get("custom_servers") or [],
            "ids_by_scene": info.get("ids_by_scene") or {},
            "kinds": kinds,
        })
    uniq: dict[str, dict[str, Any]] = {}
    for h in hits:
        key = h["captcha_id"] or h["gt"] or ",".join(h["custom_servers"][:2]) or h["file"]
        uniq.setdefault(key, h)
    out = {"ts": _now(), "path": str(root), "count": len(uniq), "hits": list(uniq.values())}
    p = save(args.case, "harvest.json", out)
    print(f"[+] harvest {len(uniq)} → {p}")
    for h in list(uniq.values())[:20]:
        print(f"  {h.get('captcha_id') or '-'}  {h.get('api_subdomain') or '-'}  ← {h['file']}")
    if uniq:
        print("  next: token --captcha-id <id> 或 solve --url <授权登录页>")
    return 0


def cmd_selftest(_args: argparse.Namespace) -> int:
    cols = [1.0] * 80 + [99.0] + [2.0] * 40
    assert gap_from_columns(cols, skip=40) == 80
    tr = human_track(120, steps=30)
    assert abs(tr[-1][0] - 120) < 0.01
    html = 'initGeetest({gt:"abcdef0123456789abcdef0123456789",challenge:"aabbccdd"})'
    info = classify_html(html)
    assert "geetest" in info["kinds"]
    assert info["gt"].startswith("abcdef")
    html4 = 'captchaId:"62c528ead784206de7e6db17765b9ac0" gcaptcha4-hrc.geetest.com'
    info4 = classify_html(html4)
    assert info4["geetest_version"] == "v4"
    assert info4["captcha_id"] == "62c528ead784206de7e6db17765b9ac0"
    rec = classify_html('<div class="g-recaptcha" data-sitekey="6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI">')
    assert "recaptcha" in rec["kinds"] and rec["sitekey"].startswith("6Le")
    assert "turnstile" in classify_html("challenges.cloudflare.com/turnstile")["kinds"]
    j = parse_geetest_body('geetest_123({"lot_number":"a","pass_token":"b"})')
    assert j and j["lot_number"] == "a" and interesting_token(j)
    sysinfo = '{"geetest_captcha_id":{"login":"aabbccddeeff00112233445566778899","force_geetest":"aabbccddeeff00112233445566778899"},"clientServer":"bcaptcha-botion.vccgeetest.com"}'
    pulled = extract_ids(sysinfo)
    assert pulled["captcha_id"] == "aabbccddeeff00112233445566778899"
    assert pulled["ids_by_scene"]["login"] == "aabbccddeeff00112233445566778899"
    assert "vccgeetest.com" in pulled["api_subdomain"]
    assert "geetest" in classify_html("bcaptcha-botion.vccgeetest.com")["kinds"]
    assert classify_html(sysinfo)["geetest_version"] == "v4"
    wrap = parse_geetest_body('{"code":0,"data":{"lot_number":"x","pass_token":"y"}}')
    assert wrap and wrap["lot_number"] == "x" and interesting_token(wrap)
    assert not interesting_token({"challenge": "old", "validate": "no"})
    assert normalize_subdomain("https://bcaptcha-botion.vccgeetest.com/load") == "bcaptcha-botion.vccgeetest.com"
    gee = classify_html('{"captchaId":"aabbccddeeff00112233445566778899"}')
    assert gee["geetest_version"] == "v4"
    sys.path.insert(0, str(ENGINE))
    from engine.proxy_pool import selftest as proxy_selftest, to_playwright
    proxy_selftest()
    cfg = to_playwright("http://u:p@hide.example:5050")
    assert cfg["server"] == "http://hide.example:5050" and cfg["username"] == "u"
    print("[selftest] ok")
    return 0


def _add_browser_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--headless", action="store_true")
    p.add_argument(
        "--proxy",
        default="",
        help="代理 URL，或 pool/auto 从 config/proxy-nodes.txt 取 HTTP 节点（禁止 SSH 用户主机）",
    )
    p.add_argument("--timeout-ms", type=int, default=90000)


def main() -> int:
    load_key_files()
    ap = argparse.ArgumentParser(description="验证码自动化（授权范围内）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("doctor", help="检查 Playwright / OCR / 打码 Key")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("detect", help="识别类型并抽取 captchaId/sitekey")
    p.add_argument("--url", required=True)
    p.add_argument("--case", required=True)
    p.add_argument("--browser", action="store_true")
    p.add_argument("--insecure", action="store_true")
    p.add_argument("--probe-api", action="store_true", help="顺手打 getGeeCaptcha / getSysInfo")
    _add_browser_args(p)
    p.set_defaults(func=cmd_detect, timeout_ms=60000)

    p = sub.add_parser("slide", help="本机有头真鼠标滑极验，并写入会话目录")
    p.add_argument("--url", required=True)
    p.add_argument("--case", required=True)
    p.add_argument("--click", default="")
    p.add_argument("--retries", type=int, default=4)
    _add_browser_args(p)
    p.set_defaults(func=cmd_slide)

    p = sub.add_parser("token", help="打码平台换 token（极验/reCAPTCHA/Turnstile）")
    p.add_argument("--url", required=True)
    p.add_argument("--case", required=True)
    p.add_argument("--kind", default="auto", choices=("auto", "geetest", "recaptcha", "turnstile"))
    p.add_argument("--captcha-id", default="")
    p.add_argument("--gt", default="")
    p.add_argument("--challenge", default="")
    p.add_argument("--sitekey", default="")
    p.add_argument("--version", type=int, default=0, help="0=跟 detect；3 或 4")
    p.add_argument("--api-subdomain", default="", help="白标极验 load 域，如 bcaptcha-botion.vccgeetest.com")
    p.set_defaults(func=cmd_token)

    p = sub.add_parser("ocr", help="从页面抽验证码图并 ddddocr")
    p.add_argument("--url", required=True)
    p.add_argument("--case", required=True)
    p.add_argument("--image-url", default="")
    p.add_argument("--beta", action="store_true")
    p.set_defaults(func=cmd_ocr)

    p = sub.add_parser("solve", help="探测后自动选 OCR / 滑块 / 打码")
    p.add_argument("--url", required=True)
    p.add_argument("--case", required=True)
    p.add_argument("--captcha-id", default="")
    p.add_argument("--gt", default="")
    p.add_argument("--challenge", default="")
    p.add_argument("--sitekey", default="")
    p.add_argument("--kind", default="auto")
    p.add_argument("--version", type=int, default=0)
    p.add_argument("--click", default="")
    p.add_argument("--retries", type=int, default=4)
    p.add_argument("--image-url", default="")
    p.add_argument("--beta", action="store_true")
    p.add_argument("--probe-api", action="store_true")
    p.add_argument("--api-subdomain", default="")
    _add_browser_args(p)
    p.set_defaults(func=cmd_solve)

    p = sub.add_parser("harvest", help="从案卷 JS/JSON 抽极验 ID / 白标 CDN")
    p.add_argument("--path", required=True)
    p.add_argument("--case", required=True)
    p.set_defaults(func=cmd_harvest)

    p = sub.add_parser("selftest", help="本地单测（不打站）")
    p.set_defaults(func=cmd_selftest)

    args = ap.parse_args()
    return int(args.func(args) or 0)


if __name__ == "__main__":
    sys.exit(main())
