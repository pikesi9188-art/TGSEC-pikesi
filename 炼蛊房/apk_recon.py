#!/usr/bin/env python3
"""APK/IPA 逆向情报提取 — 博彩站专项。

从移动端 APP 中一键提取：
  · API 基础 URL / 后台管理路径
  · 硬编码密钥（AES/DES/SM4/RSA/MD5 盐）
  · 签名算法实现（sign / md5sign / hmac）
  · WebSocket / MQTT 地址
  · 隐藏路由（/admin/ /operator/ /agent/ /backend/）
  · 第三方 SDK key（Firebase / JPush / 极光 / Umeng）
  · 测试/预发布环境 URL

依赖：jadx（tools/arsenal/jadx/bin/jadx）+ Java 17（Temurin）
安装：bash 炼蛊房/install_jadx.sh

示例:
  python3 炼蛊房/apk_recon.py doctor
  python3 炼蛊房/apk_recon.py extract --apk /tmp/app.apk --case 站点_日期
  python3 炼蛊房/apk_recon.py strings --apk /tmp/app.apk --case 站点_日期
  python3 炼蛊房/apk_recon.py sign-algo --apk /tmp/app.apk --case 站点_日期
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, UTC
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
OPS = Path(__file__).resolve().parent
ARSENAL = ENGINE / "tools" / "arsenal"
JADX_BIN = ARSENAL / "jadx" / "bin" / "jadx"
JAVA_HOME_CANDIDATES = [
    ENGINE / "tools" / "spring-gateway-killchain" / "vendor" / "jdk-17" / "Contents" / "Home",
    Path("/Library/Java/JavaVirtualMachines").glob("*/Contents/Home") if Path("/Library/Java/JavaVirtualMachines").exists() else [],
]

if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def case_dir(case: str) -> Path:
    d = ENGINE / "案卷" / case / "测绘" / "apk"
    d.mkdir(parents=True, exist_ok=True)
    return d


def find_java() -> str | None:
    for c in JAVA_HOME_CANDIDATES:
        if isinstance(c, Path) and (c / "bin" / "java").is_file():
            return str(c / "bin" / "java")
        elif hasattr(c, '__iter__'):
            for item in c:
                if (item / "bin" / "java").is_file():
                    return str(item / "bin" / "java")
    return shutil.which("java")


def find_jadx() -> str | None:
    if JADX_BIN.is_file():
        return str(JADX_BIN)
    return shutil.which("jadx")


def java_env() -> dict:
    java = find_java()
    if not java:
        return {}
    env = dict(os.environ)
    java_home = str(Path(java).parents[1])
    env["JAVA_HOME"] = java_home
    env["PATH"] = str(Path(java).parent) + ":" + env.get("PATH", "")
    return env


def decompile_apk(apk_path: str, out_dir: Path, timeout: int = 300) -> tuple[int, str]:
    """用 jadx 反编译 APK 到 out_dir。"""
    jadx = find_jadx()
    if not jadx:
        return 127, "jadx not found — run: bash 炼蛊房/install_jadx.sh"
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [jadx, "--output-dir", str(out_dir), "--no-res", apk_path]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=java_env())
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, "jadx timeout"
    except Exception as exc:
        return 1, str(exc)


# ─────────────────────────────────────────────
#  情报提取规则
# ─────────────────────────────────────────────

# API URL 模式
URL_PATTERNS = [
    re.compile(r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]{8,200}', re.I),
    re.compile(r'wss?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]{8,200}', re.I),
    re.compile(r'mqtt://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]{8,200}', re.I),
]

# 硬编码密钥模式
KEY_PATTERNS = {
    "aes_key": re.compile(r'(?:key|aes|secret|encrypt).*?["\']([0-9A-Fa-f]{16,64})["\']', re.I),
    "md5_salt": re.compile(r'(?:salt|md5key|signkey|apikey|appsecret).*?["\']([0-9A-Za-z+/=_\-]{8,80})["\']', re.I),
    "jwt_secret": re.compile(r'(?:jwt|token|secret).*?["\']([A-Za-z0-9+/=_\-]{20,120})["\']', re.I),
    "hex_key_16": re.compile(r'["\']([0-9A-F]{32})["\']'),   # 16 bytes hex AES-128
    "hex_key_32": re.compile(r'["\']([0-9A-F]{64})["\']'),   # 32 bytes hex AES-256
    "firebase_key": re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
    "jpush_key": re.compile(r'(?:appKey|app_key|jpush).*?["\']([0-9a-f]{24})["\']', re.I),
    "cognito_pool": re.compile(
        r'\b((?:us|us-gov|ap|eu|sa|ca|me|af|cn|il)-[a-z]+-\d:'
        r'[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12})\b'
    ),
}

# 后台路径模式
ADMIN_PATH_PATTERNS = [
    re.compile(r'["\'/](?:admin|backend|operator|manage|boss|platform|super)[/"\'_\-]', re.I),
    re.compile(r'["\'/](?:api/admin|api/manage|api/operator)[/"\'_\-]', re.I),
]

# 签名算法特征
SIGN_PATTERNS = {
    "md5_sign": re.compile(r'(?:sign|signature|checkSign).*?MD5|MessageDigest.*?MD5', re.I),
    "hmac_sign": re.compile(r'HmacSHA\d+|hmac.*?sha', re.I),
    "aes_usage": re.compile(r'AES/(?:CBC|ECB|GCM)/\w+', re.I),
    "sm4_usage": re.compile(r'SM4|"SM4"', re.I),
    "des_usage": re.compile(r'"DES"|DESede', re.I),
    "rsa_usage": re.compile(r'RSA/\w+|"RSA"', re.I),
}

# 测试/预发布环境
TEST_ENV_PATTERNS = [
    re.compile(r'https?://(?:test|dev|staging|uat|beta|sandbox|qa)[.\-][a-zA-Z0-9\-._]+', re.I),
    re.compile(r'https?://[a-zA-Z0-9\-._]+\.(?:test|dev|local|internal)\b', re.I),
]

# 第三方 SDK
SDK_PATTERNS = {
    "firebase": re.compile(r'AIza[0-9A-Za-z\-_]{35}|firebase.*?["\']([^"\']{20,})["\']', re.I),
    "jpush": re.compile(r'["\']([0-9a-f]{24})["\'].*?jpush|jpush.*?["\']([0-9a-f]{24})["\']', re.I),
    "umeng": re.compile(r'umeng.*?["\']([0-9a-f]{24})["\']|["\']([0-9a-f]{24})["\'].*?umeng', re.I),
    "agora": re.compile(r'agora.*?appId.*?["\']([0-9a-f]{32})["\']', re.I),
    "tencent_push": re.compile(r'ACCESS_ID.*?["\'](\d{10,})["\']', re.I),
}

# 数据库/内网地址
INTERNAL_PATTERNS = [
    re.compile(r'(?:jdbc|mysql|redis|mongo|postgresql)://[^\s"\'<>]{5,100}', re.I),
    re.compile(r'(?:host|hostname|server).*?["\'](\d{1,3}(?:\.\d{1,3}){3})["\']', re.I),
    re.compile(r'192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+'),
]


def scan_file(filepath: Path) -> dict:
    """扫描单个文件，返回各类情报。"""
    result = {
        "urls": set(),
        "keys": {},
        "admin_paths": set(),
        "sign_algos": set(),
        "test_envs": set(),
        "sdks": {},
        "internals": set(),
    }
    try:
        text = filepath.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return result

    for p in URL_PATTERNS:
        for m in p.findall(text):
            # 过滤常见误报
            if any(skip in m for skip in ("example.com", "schema.org", "w3.org", "android.", "google.com/maps")):
                continue
            result["urls"].add(m[:200])

    for key_type, p in KEY_PATTERNS.items():
        found = p.findall(text)
        if found:
            result["keys"].setdefault(key_type, set()).update(
                [f if isinstance(f, str) else f[0] for f in found[:10]]
            )

    for p in ADMIN_PATH_PATTERNS:
        for m in p.findall(text):
            result["admin_paths"].add(m.strip("\"'"))

    for algo, p in SIGN_PATTERNS.items():
        if p.search(text):
            result["sign_algos"].add(algo)

    for p in TEST_ENV_PATTERNS:
        for m in p.findall(text):
            result["test_envs"].add(m[:150])

    for sdk, p in SDK_PATTERNS.items():
        found = p.findall(text)
        if found:
            result["sdks"].setdefault(sdk, set()).update(
                [f if isinstance(f, str) else (f[0] or f[1]) for f in found[:5]]
            )

    for p in INTERNAL_PATTERNS:
        for m in p.findall(text):
            result["internals"].add(m[:100])

    return result


def merge_results(results: list[dict]) -> dict:
    merged = {
        "urls": set(),
        "keys": {},
        "admin_paths": set(),
        "sign_algos": set(),
        "test_envs": set(),
        "sdks": {},
        "internals": set(),
    }
    for r in results:
        merged["urls"].update(r.get("urls") or set())
        merged["admin_paths"].update(r.get("admin_paths") or set())
        merged["sign_algos"].update(r.get("sign_algos") or set())
        merged["test_envs"].update(r.get("test_envs") or set())
        merged["internals"].update(r.get("internals") or set())
        for k, v in (r.get("keys") or {}).items():
            merged["keys"].setdefault(k, set()).update(v)
        for k, v in (r.get("sdks") or {}).items():
            merged["sdks"].setdefault(k, set()).update(v)
    return merged


def results_to_json_safe(r: dict) -> dict:
    def conv(v):
        if isinstance(v, set):
            return sorted(v)
        if isinstance(v, dict):
            return {k2: conv(v2) for k2, v2 in v.items()}
        return v
    return {k: conv(v) for k, v in r.items()}


# ─────────────────────────────────────────────
#  命令
# ─────────────────────────────────────────────
def cmd_doctor(_: argparse.Namespace) -> int:
    jadx = find_jadx()
    java = find_java()
    print(f"[{'ok' if jadx else 'missing'}] jadx: {jadx or '-'}")
    print(f"[{'ok' if java else 'missing'}] java: {java or '-'}")
    if java:
        r = subprocess.run([java, "-version"], capture_output=True, text=True)
        print(f"  {(r.stderr or r.stdout).splitlines()[0]}")
    if not jadx:
        print("  hint: bash 炼蛊房/install_jadx.sh")
    if jadx and java:
        env = java_env()
        r = subprocess.run([jadx, "--version"], capture_output=True, text=True, env=env)
        print(f"  jadx version: {(r.stdout or r.stderr).strip()}")
    print("[ok] apk_recon ready")
    return 0


def cmd_extract(args: argparse.Namespace) -> int:
    """完整流程：反编译 → 扫描所有 Java/smali 文件 → 落证据。"""
    apk = Path(args.apk)
    if not apk.is_file():
        raise SystemExit(f"[err] APK not found: {apk}")

    out = case_dir(args.case)
    decompile_dir = out / "decompiled"
    print(f"[*] decompiling {apk.name} → {decompile_dir}", flush=True)
    rc, log = decompile_apk(str(apk), decompile_dir, timeout=args.timeout)
    (out / "jadx.log").write_text(log, encoding="utf-8")
    if rc not in (0, 1):  # jadx exit 1 = warnings only
        print(f"[!] jadx rc={rc}. Log: {out/'jadx.log'}")

    # 收集所有 .java 和 smali 文件
    java_files = list(decompile_dir.rglob("*.java")) + list(decompile_dir.rglob("*.kt"))
    print(f"[*] scanning {len(java_files)} source files …", flush=True)

    all_results = []
    for i, f in enumerate(java_files):
        all_results.append(scan_file(f))
        if (i + 1) % 500 == 0:
            print(f"  [{i+1}/{len(java_files)}]", flush=True)

    merged = merge_results(all_results)
    safe = results_to_json_safe(merged)

    # 过滤 URL：只保留看起来像目标的（去掉 SDK/analytics 域）
    noise_domains = [
        "google", "firebase", "crashlytics", "bugsnag", "sentry",
        "amazonaws.com", "cloudfront", "akamai", "githubusercontent",
        "android.com", "mozilla.org", "w3.org", "schema.org",
        "appcenter.ms", "microsoft.com", "apple.com", "icloud",
    ]
    target_urls = [u for u in safe["urls"] if not any(n in u.lower() for n in noise_domains)]
    safe["target_urls"] = sorted(set(target_urls))

    # 按类别分组输出
    report = {
        "ts": _now(),
        "apk": str(apk),
        "case": args.case,
        "jadx_files": len(java_files),
        "target_urls": safe["target_urls"],
        "test_envs": safe["test_envs"],
        "admin_paths": safe["admin_paths"],
        "sign_algorithms": safe["sign_algos"],
        "hardcoded_keys": safe["keys"],
        "sdk_keys": safe["sdks"],
        "internal_addresses": safe["internals"],
        "all_urls": safe["urls"],
    }

    out_json = out / "apk_intel.json"
    out_json.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    # 打印重点情报
    print(f"\n{'='*60}")
    print(f"APK 情报提取结果 — {apk.name}")
    print(f"{'='*60}")

    if report["target_urls"]:
        print(f"\n[API URLs] ({len(report['target_urls'])} 个)")
        for u in report["target_urls"][:30]:
            print(f"  {u}")

    if report["test_envs"]:
        print(f"\n[测试/预发布环境] ({len(report['test_envs'])} 个) ← 高优先级")
        for u in report["test_envs"]:
            print(f"  ★ {u}")

    if report["admin_paths"]:
        print(f"\n[后台路径] ({len(report['admin_paths'])} 个) ← 高优先级")
        for p in sorted(report["admin_paths"])[:20]:
            print(f"  ★ {p}")

    if report["sign_algorithms"]:
        print("\n[签名算法]")
        for a in report["sign_algorithms"]:
            print(f"  {a}")

    if report["hardcoded_keys"]:
        print("\n[硬编码密钥] ← 直接用于 API 伪造")
        for kt, keys in report["hardcoded_keys"].items():
            for k in list(keys)[:5]:
                print(f"  [{kt}] {k}")
        pools = report["hardcoded_keys"].get("cognito_pool") or []
        if pools:
            print("\n[Cognito] ★ IdentityPoolId → cognito-unauth-s3-chain")
            print("  next: python3 炼蛊房/cognito_s3_probe.py chain --app-host <授权域> --pool-id '<id>' --case <案卷>")

    if report["internal_addresses"]:
        print("\n[内网地址/数据库]")
        for a in report["internal_addresses"][:10]:
            print(f"  {a}")

    if report["sdk_keys"]:
        print("\n[第三方 SDK keys]")
        for sdk, keys in report["sdk_keys"].items():
            for k in list(keys)[:3]:
                print(f"  [{sdk}] {k}")

    print(f"\n[+] 完整报告 → {out_json}")
    return 0


def cmd_strings(args: argparse.Namespace) -> int:
    """不反编译，直接用 strings 快速提取 APK 中的字符串（速度快 10x）。"""
    apk = Path(args.apk)
    if not apk.is_file():
        raise SystemExit(f"[err] APK not found: {apk}")
    out = case_dir(args.case)

    # APK 是 ZIP，直接解压 classes.dex 等
    import zipfile
    print(f"[*] extracting strings from {apk.name} …", flush=True)
    all_text = []
    try:
        with zipfile.ZipFile(str(apk)) as zf:
            for name in zf.namelist():
                if name.endswith((".dex", ".so", ".js", ".json", ".xml", ".plist")):
                    try:
                        data = zf.read(name).decode("utf-8", errors="replace")
                        all_text.append(data)
                    except Exception:
                        pass
    except Exception as exc:
        print(f"[!] zip error: {exc}")
        return 1

    combined = "\n".join(all_text)
    fake_path = out / "_combined_strings.txt"
    fake_path.write_text(combined[:5_000_000], encoding="utf-8")  # 最多 5MB

    result = scan_file(fake_path)
    fake_path.unlink()  # 清理临时文件
    safe = results_to_json_safe(result)

    out_json = out / "apk_strings_intel.json"
    out_json.write_text(json.dumps({"ts": _now(), "apk": str(apk), **safe},
                                   ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    # 快速打印
    all_urls = [u for u in safe.get("urls", [])
                if not any(n in u.lower() for n in ("google", "firebase", "android", "schema", "w3"))]
    print(f"[URLs] {len(all_urls)} 个")
    for u in all_urls[:20]:
        print(f"  {u}")
    if safe.get("test_envs"):
        print(f"[测试环境] ★ {safe['test_envs']}")
    if safe.get("keys"):
        print(f"[密钥] {safe['keys']}")
    pools = (safe.get("keys") or {}).get("cognito_pool") or []
    if pools:
        print(f"[Cognito] ★ IdentityPoolId {pools}")
        print("  next: python3 炼蛊房/cognito_s3_probe.py extract --path <apk> --case <案卷>")
        print("        python3 炼蛊房/cognito_s3_probe.py chain --app-host <授权域> --pool-id '<id>' --case <案卷>")
        print("  Skill: cognito-unauth-s3-chain")
    print(f"[+] → {out_json}")
    return 0


def cmd_sign_algo(args: argparse.Namespace) -> int:
    """专项：反编译后只找签名算法实现，输出关键代码片段。"""
    apk = Path(args.apk)
    out = case_dir(args.case)
    decompile_dir = out / "decompiled"

    if not decompile_dir.exists():
        print("[*] decompiling first …", flush=True)
        decompile_apk(str(apk), decompile_dir, timeout=args.timeout)

    java_files = list(decompile_dir.rglob("*.java"))
    findings = []
    for f in java_files:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for algo, p in SIGN_PATTERNS.items():
            if p.search(text):
                # 找包含签名的函数
                for fn_match in re.finditer(
                    r"(?:public|private|protected)\s+.*?(?:sign|encrypt|encode|hash|digest|md5|aes|hmac)[^{]{0,100}\{[^}]{0,500}\}",
                    text, re.I | re.S
                ):
                    findings.append({
                        "file": str(f.relative_to(decompile_dir)),
                        "algo": algo,
                        "snippet": fn_match.group(0)[:600],
                    })

    out_json = out / "sign_algo.json"
    out_json.write_text(json.dumps({"ts": _now(), "findings": findings[:50]},
                                   ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"[*] {len(findings)} 签名函数 → {out_json}")
    for f in findings[:5]:
        print(f"\n  [{f['algo']}] {f['file']}")
        print("  " + f["snippet"][:300].replace("\n", "\n  "))
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="APK 逆向情报提取（博彩站专项）")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("doctor")
    d.set_defaults(func=cmd_doctor)

    ex = sub.add_parser("extract", help="完整反编译 + 情报提取（慢，全面）")
    ex.add_argument("--apk", required=True)
    ex.add_argument("--case", required=True)
    ex.add_argument("--timeout", type=int, default=300, help="jadx 超时秒数")
    ex.set_defaults(func=cmd_extract)

    st = sub.add_parser("strings", help="快速 strings 提取（不反编译，30秒内）")
    st.add_argument("--apk", required=True)
    st.add_argument("--case", required=True)
    st.set_defaults(func=cmd_strings)

    sa = sub.add_parser("sign-algo", help="专项：找签名算法实现")
    sa.add_argument("--apk", required=True)
    sa.add_argument("--case", required=True)
    sa.add_argument("--timeout", type=int, default=300)
    sa.set_defaults(func=cmd_sign_algo)

    args = p.parse_args()
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
