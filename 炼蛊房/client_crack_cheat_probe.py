#!/usr/bin/env python3
"""大爱仙尊客户端破解 / 外挂作业链（授权样本或授权站）。

子命令:
  drive    本地样本一键：认族 → 抽 metadata/dump.cs（含 APK 内）→ 出 Frida/CE
  meta     解析 global-metadata.dat 字符串与结算名
  hooks    根据 dump.cs / 字符串生成可跑 Frida
  replay   对授权接口改分/币/胜负字段，对照基线
  memscan  在内存转储里扫整数/字符串（CE 同思路）

L2 = 服务端吃伪造状态，或 hook 已落到可按类名/RVA attach 的脚本。
不生成公网游戏现成瞄准挂。验证码/哈希破解不走这里。
"""
from __future__ import annotations

import argparse
import json
import re
import struct
import sys
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))

IL2CPP_SANITY = 0xFAB11BAF
ZIP_EXT = {".apk", ".ipa", ".zip", ".xapk", ".apks"}
CS_MOD = r"(?:static|override|virtual|abstract|extern|new|sealed|unsafe|async|readonly|partial)\s+"
HOOK_NAME = re.compile(
    r"(gold|score|chip|coin|diamond|win|lose|reward|settle|balance|"
    r"license|vip|paid|unlock|damage|hp|ammo|send|packet|rpc|room|"
    r"battle|result|integrity|safetynet|emulator|root)",
    re.I,
)
CLASS_RE = re.compile(
    r"(?:public|private|internal|protected)\s+"
    r"(?:abstract\s+|sealed\s+|static\s+|partial\s+)*class\s+([\w.]+)"
)
METHOD_RE = re.compile(
    rf"(?:public|private|internal|protected)\s+(?:{CS_MOD})*"
    r"(?:[\w.<>,\[\]\s*&]+?)\s+(\w+)\s*(?:<[^>]+>)?\s*\("
)
DUMP_RVA = re.compile(r"RVA:\s*(0x[0-9A-Fa-f]+)")
SETTLE_KEYS = (
    "gold", "score", "balance", "win", "isWinner", "chip", "reward",
    "ok", "code", "success", "amount", "coin",
)
ENGINE = (
    (b"GameAssembly", "il2cpp"),
    (b"global-metadata", "il2cpp-metadata"),
    (b"UnityPlayer", "unity"),
    (b"UnityEngine", "unity"),
    (b"il2cpp", "il2cpp"),
    (b"UE4Game", "unreal"),
    (b"UnrealEngine", "unreal"),
    (b"Cocos2d", "cocos"),
    (b"libcocos2d", "cocos"),
)
ANTICHEAT = (
    (b"EasyAntiCheat", "eac"),
    (b"EasyAntiCheat_EOS", "eac"),
    (b"BattlEye", "battleye"),
    (b"BEClient", "battleye"),
    (b"ACE-Base", "ace"),
    (b"Tenprotect", "tp"),
    (b"NPGameDLL", "tp"),
    (b"mhyprot", "mhyprot"),
    (b"nprotect", "nprotect"),
)
STATE = (
    b"playerGold", b"player_gold", b"chipCount", b"winAmount", b"isWinner",
    b"gameScore", b"battleResult", b"roomSnapshot", b"clientScore",
    b"localScore", b"canSkip", b"autoWin", b"isLicensed", b"CheckLicense",
)
NAME_HINTS = (
    "gameassembly.dll", "unityplayer.dll", "global-metadata.dat",
    "easyanticheat", "beclient", "assembly-csharp.dll",
)
GAME_API = (
    "/api/game/settle", "/api/game/result", "/api/battle/result",
    "/api/room/sync", "/api/player/state", "/api/wallet/chip",
    "/game/settle", "/game/result", "/api/score", "/api/reward",
)
SKIP_HTTP = {404, 405, 502, 503}
FRIDA_IL2CPP = """// 大爱仙尊 crack-cheat · IL2CPP hook
// frida -U -f <包名> -l {name} --no-pause
// 有 RVA 时不依赖 bridge；按类名 hook：npm i frida-il2cpp-bridge
'use strict';
rpc.exports = {{ ping: function () {{ return 'se-ok'; }} }};

function gameBase() {{
  return Module.findBaseAddress('GameAssembly.dll')
      || Module.findBaseAddress('libil2cpp.so')
      || Module.findBaseAddress('GameAssembly.so');
}}

function forceTruthy(method, retval) {{
  const n = String(method || '').toLowerCase();
  if (n.indexOf('license') >= 0 || n.indexOf('vip') >= 0 ||
      n.indexOf('paid') >= 0 || n.indexOf('unlock') >= 0) {{
    try {{ retval.replace(ptr(1)); console.log('[SE] force true ' + method); }}
    catch (e) {{}}
  }}
}}

function hookRva(rva, klass, method) {{
  const base = gameBase();
  if (!base) {{ console.log('[SE] no GameAssembly/libil2cpp'); return; }}
  try {{
    Interceptor.attach(base.add(ptr(rva)), {{
      onLeave(retval) {{
        console.log('[SE] RVA ' + rva + ' ' + klass + '.' + method + ' ret=' + retval);
        forceTruthy(method, retval);
      }}
    }});
    console.log('[SE] rva hooked ' + klass + '.' + method + ' @ ' + rva);
  }} catch (e) {{
    console.log('[SE] rva miss ' + rva + ' ' + e);
  }}
}}

function hookOne(klass, method) {{
  if (typeof Il2Cpp === 'undefined') {{
    console.log('[SE] skip class hook (no bridge) ' + klass + '.' + method);
    return;
  }}
  try {{
    const short = klass.split('.').pop();
    const img = Il2Cpp.domain.assembly('Assembly-CSharp').image;
    let k;
    try {{ k = img.class(short); }} catch (e) {{ k = img.class(klass); }}
    const m = k.method(method);
    Interceptor.attach(m.virtualAddress, {{
      onLeave(retval) {{
        console.log('[SE] ' + klass + '.' + method + ' ret=' + retval);
        forceTruthy(method, retval);
      }}
    }});
    console.log('[SE] hooked ' + klass + '.' + method);
  }} catch (e) {{
    console.log('[SE] miss ' + klass + '.' + method + ' ' + e);
  }}
}}

{rva_body}

function runClassHooks() {{
{body}
}}

try {{
  const bridge = require('frida-il2cpp-bridge');
  globalThis.Il2Cpp = bridge.Il2Cpp || bridge;
  Il2Cpp.perform(runClassHooks);
}} catch (e) {{
  console.log('[SE] bridge: ' + e);
  runClassHooks();
}}
"""
FRIDA_NET = """// 大爱仙尊 crack-cheat · send/recv
// frida -U -n <进程> -l {name}
'use strict';
function hex(p, n) {{
  try {{ return hexdump(p, {{ length: Math.min(n, 64), ansi: false }}); }}
  catch (e) {{ return ''; }}
}}
['send', 'sendto', 'recv', 'recvfrom'].forEach(function (fn) {{
  const addr = Module.findExportByName(null, fn);
  if (!addr) return;
  Interceptor.attach(addr, {{
    onEnter(args) {{
      this.fn = fn;
      this.buf = args[1];
      this.len = fn.indexOf('send') === 0 ? args[2].toInt32() : 0;
    }},
    onLeave(retval) {{
      const n = this.fn.indexOf('recv') === 0 ? retval.toInt32() : this.len;
      if (n > 8) console.log('[SE] ' + this.fn + ' ' + n + '\\n' + hex(this.buf, n));
    }}
  }});
  console.log('[SE] ' + fn + ' @ ' + addr);
}});
"""
FRIDA_JAVA = """// 大爱仙尊 crack-cheat · Java 结算/授权
// frida -U -f <包名> -l {name} --no-pause
Java.perform(function () {{
  var names = {classes};
  names.forEach(function (cn) {{
    try {{
      var C = Java.use(cn);
      C.class.getDeclaredMethods().forEach(function (m) {{
        var n = m.getName();
        if (!/gold|score|win|license|vip|paid|settle|reward/i.test(n)) return;
        try {{
          C[n].overloads.forEach(function (ov) {{
            ov.implementation = function () {{
              var ret = ov.apply(this, arguments);
              console.log('[SE] ' + cn + '.' + n + ' -> ' + ret);
              return ret;
            }};
          }});
        }} catch (e) {{}}
      }});
      console.log('[SE] java ' + cn);
    }} catch (e) {{}}
  }});
}});
"""
CE_LUA = """-- 大爱仙尊 · Cheat Engine 值猎（授权进程）
-- 1) 附加目标  2) 扫当前金币  3) 花一笔再扫  4) 锁定后打服务端接口验证
-- 本文件只给步骤，不替你点 CE。
local se_hint = "{hint}"
print("[SE] first scan exact: " .. se_hint)
print("[SE] next: spend/gain then next scan; freeze != L2")
print("[SE] L2 = HTTP/TCP 结算包带上改过的值且服务器认")
"""


def classify_blob(data: bytes, names: list[str] | None = None) -> dict[str, Any]:
    blob = data[: 256 * 1024]
    low = blob.lower()
    name_l = " ".join(n.lower().replace("\\", "/") for n in (names or []))
    engines: list[str] = []
    acs: list[str] = []
    states: list[str] = []
    for needle, tag in ENGINE:
        if needle.lower() in low or needle.decode("ascii", "ignore").lower() in name_l:
            if tag not in engines:
                engines.append(tag)
    for needle, tag in ANTICHEAT:
        if needle.lower() in low or needle.decode("ascii", "ignore").lower() in name_l:
            if tag not in acs:
                acs.append(tag)
    for needle in STATE:
        if needle.lower() in low:
            states.append(needle.decode("ascii"))
    for hint in NAME_HINTS:
        if hint in name_l:
            if "gameassembly" in hint or "metadata" in hint:
                if "il2cpp" not in engines:
                    engines.append("il2cpp")
            if "assembly-csharp" in hint and "unity-mono" not in engines:
                engines.append("unity-mono")
            if "unity" in hint and "unity" not in engines:
                engines.append("unity")
            if "easyanticheat" in hint and "eac" not in acs:
                acs.append("eac")
            if "beclient" in hint and "battleye" not in acs:
                acs.append("battleye")
    level = "L1" if engines or acs or states else "none"
    return {"level": level, "engines": engines, "anticheat": acs, "state_fields": states[:20]}


def _harvest_printables(data: bytes, *, limit: int) -> list[str]:
    out: list[str] = []
    for m in re.finditer(rb"[\x20-\x7e]{4,80}", data[: 2 * 1024 * 1024]):
        s = m.group().decode("ascii")
        if HOOK_NAME.search(s):
            out.append(s)
        if len(out) >= limit:
            break
    return out


def parse_il2cpp_metadata(data: bytes, *, limit: int = 400) -> dict[str, Any]:
    if len(data) < 24:
        return {"ok": False, "reason": "too-small"}
    sanity, version = struct.unpack_from("<II", data, 0)
    literals: list[str] = []
    if sanity != IL2CPP_SANITY:
        literals = _harvest_printables(data, limit=limit)
        hooks = [s for s in literals if HOOK_NAME.search(s)]
        return {
            "ok": False,
            "reason": "not-il2cpp-metadata",
            "sanity": hex(sanity),
            "literals": literals[:limit],
            "hook_names": hooks[:120],
            "level": "L1" if hooks else "none",
        }
    pairs: list[tuple[int, int]] = []
    off = 8
    while off + 8 <= min(len(data), 8 + 96 * 8):
        o, s = struct.unpack_from("<II", data, off)
        pairs.append((o, s))
        off += 8
    if len(pairs) >= 2:
        lit_off, lit_size = pairs[0]
        data_off, data_size = pairs[1]
        if (
            lit_size >= 8
            and lit_off + lit_size <= len(data)
            and data_off + data_size <= len(data)
            and lit_size % 8 == 0
        ):
            for i in range(0, min(lit_size, 8 * 8000), 8):
                length, idx = struct.unpack_from("<II", data, lit_off + i)
                if length == 0 or length > 512 or idx + length > data_size:
                    continue
                raw = data[data_off + idx : data_off + idx + length]
                try:
                    s = raw.decode("utf-8")
                except UnicodeDecodeError:
                    continue
                if HOOK_NAME.search(s) or s.isidentifier():
                    literals.append(s)
                if len(literals) >= limit:
                    break
    if not literals:
        literals = _harvest_printables(data, limit=limit)
    hooks = [s for s in literals if HOOK_NAME.search(s)]
    return {
        "ok": True,
        "version": version,
        "header_pairs": len(pairs),
        "literals": literals[:limit],
        "hook_names": hooks[:120],
        "level": "L1" if hooks or literals else "none",
    }


def parse_dump_cs(text: str, *, limit: int = 80) -> list[dict[str, str]]:
    hits: list[dict[str, str]] = []
    klass = ""
    last_rva = ""
    skip_names = {"get", "set", "Equals", "ToString", "GetHashCode", "Finalize"}
    for line in text.splitlines():
        if line.lstrip().startswith(("//", "#", "/*")):
            rv = DUMP_RVA.search(line)
            if rv:
                last_rva = rv.group(1)
            continue
        rv = DUMP_RVA.search(line)
        code = line.split("//", 1)[0]
        if rv and "(" not in code:
            last_rva = rv.group(1)
        cm = CLASS_RE.search(code)
        if cm:
            klass = cm.group(1).rsplit(".", 1)[-1]
            last_rva = ""
            continue
        mm = METHOD_RE.search(line)
        if not mm or not klass:
            continue
        name = mm.group(1)
        if name in skip_names or name.startswith("<") or klass.startswith("<"):
            last_rva = ""
            continue
        if not (HOOK_NAME.search(klass) or HOOK_NAME.search(name)):
            last_rva = ""
            continue
        rva = rv.group(1) if rv else last_rva
        last_rva = ""
        hits.append({"class": klass, "method": name, "rva": rva})
        if len(hits) >= limit:
            break
    return hits


def pick_hook_targets(
    dump_hits: list[dict[str, str]], meta_names: list[str]
) -> list[dict[str, str]]:
    out = list(dump_hits)
    seen = {(h["class"], h["method"]) for h in out}
    for name in meta_names:
        if not HOOK_NAME.search(name):
            continue
        key = ("<string>", name)
        if key in seen:
            continue
        out.append({"class": "<string>", "method": name, "rva": ""})
        seen.add(key)
        if len(out) >= 80:
            break
    return out


def hook_level(targets: list[dict[str, str]]) -> str:
    named = [t for t in targets if t.get("class") and t["class"] != "<string>"]
    if named:
        return "L2"
    if targets:
        return "L1"
    return "none"


def render_frida(targets: list[dict[str, str]]) -> dict[str, str]:
    lines: list[str] = []
    rva_lines: list[str] = []
    java_cls: list[str] = []
    for t in targets:
        klass = t["class"]
        method = t["method"]
        rva = t.get("rva") or ""
        if klass != "<string>":
            lines.append(f"  hookOne({klass!r}, {method!r});")
            if rva:
                rva_lines.append(f"hookRva({rva!r}, {klass!r}, {method!r});")
            if "." in klass or klass[:1].isupper():
                java_cls.append(klass)
        else:
            lines.append(f"  console.log('[SE] string target {method}');")
    if not lines:
        lines = ["  console.log('[SE] no class/method from dump.cs; Il2CppDumper 出 dump.cs 再 hooks');"]
    body = "\n".join(lines)
    rva_body = "\n".join(rva_lines) if rva_lines else "// no RVA from dump.cs"
    return {
        "il2cpp.js": FRIDA_IL2CPP.format(name="il2cpp.js", body=body, rva_body=rva_body),
        "net.js": FRIDA_NET.format(name="net.js"),
        "java.js": FRIDA_JAVA.format(name="java.js", classes=json.dumps(sorted(set(java_cls))[:20])),
        "ce_hint.lua": CE_LUA.format(hint="current_gold_or_score"),
    }


def _parse_scalar(raw: str) -> Any:
    if raw.lower() in {"true", "false"}:
        return raw.lower() == "true"
    try:
        return int(raw) if raw.lstrip("-").isdigit() else float(raw)
    except ValueError:
        return raw


def apply_flips(obj: Any, flips: list[str]) -> Any:
    if not isinstance(obj, dict):
        obj = {}
    out = json.loads(json.dumps(obj))
    for item in flips:
        if "=" not in item:
            continue
        key, raw = item.split("=", 1)
        key = key.strip()
        val = _parse_scalar(raw)
        if "." in key:
            cur = out
            parts = [p for p in key.split(".") if p]
            for part in parts[:-1]:
                nxt = cur.get(part)
                if not isinstance(nxt, dict):
                    cur[part] = {}
                cur = cur[part]
            if parts:
                cur[parts[-1]] = val
        else:
            out[key] = val
    return out


def scan_mem_values(data: bytes, *, value: int | None = None, text: str = "") -> dict[str, Any]:
    ints: list[int] = []
    if value is not None:
        for fmt, align in (("<i", 4), ("<q", 8)):
            try:
                packed = struct.pack(fmt, int(value))
            except struct.error:
                continue
            start = 0
            while True:
                i = data.find(packed, start)
                if i < 0:
                    break
                if i % align == 0:
                    ints.append(i)
                start = i + 1
                if len(ints) >= 80:
                    break
            if len(ints) >= 80:
                break
    strs: list[int] = []
    if text:
        needles = [text.encode("utf-8")]
        try:
            needles.append(text.encode("utf-16le"))
        except UnicodeEncodeError:
            pass
        for needle in needles:
            start = 0
            while True:
                i = data.find(needle, start)
                if i < 0:
                    break
                strs.append(i)
                start = i + 1
                if len(strs) >= 40:
                    break
    return {
        "int_hits": ints[:80],
        "str_hits": strs[:40],
        "level": "L1" if ints or strs else "none",
    }


def looks_like_html(data: bytes) -> bool:
    s = data[:240].lstrip().lower()
    return s.startswith(b"<") or b"<html" in s or b"<!doctype" in s


def _json_obj(data: bytes) -> dict[str, Any] | None:
    try:
        obj = json.loads(data.decode("utf-8", "replace"))
    except (ValueError, UnicodeDecodeError):
        return None
    return obj if isinstance(obj, dict) else None


def replay_verdict(
    base_status: int,
    flip_status: int,
    base_body: bytes,
    flip_body: bytes,
    *,
    size_ok: bool,
) -> tuple[str, str]:
    """对照基线。size_ok=False：短表扫路径，禁止只靠体长报 L2。"""
    if base_status in SKIP_HTTP and flip_status in SKIP_HTTP:
        return "L1", "dead-path"
    if flip_status == 200 and base_status in {401, 403}:
        if looks_like_html(flip_body):
            return "L1", "html-200"
        return "L2", "auth-bypass"
    if flip_status == 200 and base_status == 200:
        if looks_like_html(base_body) and looks_like_html(flip_body):
            return "L1", "both-html"
        ja, jb = _json_obj(base_body), _json_obj(flip_body)
        if ja is not None and jb is not None:
            for k in SETTLE_KEYS:
                if k in jb and ja.get(k) != jb.get(k):
                    return "L2", f"field:{k}"
            if ja.get("success") is False and jb.get("success") is True:
                return "L2", "field:success"
        if (
            size_ok
            and abs(len(flip_body) - len(base_body)) >= 40
            and not looks_like_html(flip_body)
            and flip_body != base_body
        ):
            return "L2", "size"
    return "L1", "no-delta"


def _is_zip_file(p: Path) -> bool:
    if not p.is_file():
        return False
    if p.suffix.lower() in ZIP_EXT:
        return True
    try:
        return p.read_bytes()[:2] == b"PK"
    except OSError:
        return False


def _read_from_zip(p: Path, *needles: str) -> tuple[bytes | None, str]:
    try:
        with zipfile.ZipFile(p) as zf:
            names = [n.replace("\\", "/") for n in zf.namelist()]
    except (zipfile.BadZipFile, OSError):
        return None, ""
    for needle in needles:
        nl = needle.lower()
        hit = next((n for n in names if nl == Path(n).name.lower()), None)
        if not hit:
            hit = next((n for n in names if nl in Path(n).name.lower()), None)
        if not hit:
            continue
        try:
            with zipfile.ZipFile(p) as zf:
                return zf.read(hit), hit
        except (zipfile.BadZipFile, OSError, KeyError):
            return None, ""
    return None, ""


def _find_named(root: Path, *needles: str) -> Path | None:
    if root.is_file():
        if any(n.lower() in root.name.lower() for n in needles):
            return root
        return None
    for n in needles:
        hit = next((p for p in root.rglob("*") if p.is_file() and n.lower() in p.name.lower()), None)
        if hit:
            return hit
    return None


def read_named(root: Path, *needles: str) -> tuple[bytes | None, str]:
    """目录 / 单文件 / APK·zip 内按文件名抽字节。"""
    if root.is_file():
        if any(n.lower() in root.name.lower() for n in needles):
            return root.read_bytes(), str(root)
        if _is_zip_file(root):
            return _read_from_zip(root, *needles)
        return None, ""
    hit = _find_named(root, *needles)
    if hit:
        return hit.read_bytes(), str(hit)
    if root.is_dir():
        for child in root.iterdir():
            if child.is_file() and child.suffix.lower() in ZIP_EXT:
                data, name = _read_from_zip(child, *needles)
                if data is not None:
                    return data, f"{child.name}:{name}"
    return None, ""


def scan_path(path: Path) -> dict[str, Any]:
    p = Path(path)
    names: list[str] = []
    blob = b""
    if p.is_dir():
        for child in p.rglob("*"):
            if child.is_file():
                names.append(str(child.relative_to(p)))
                if len(names) >= 800:
                    break
        for prefer in (
            "global-metadata.dat", "GameAssembly.dll", "UnityPlayer.dll",
            "Assembly-CSharp.dll", "dump.cs",
        ):
            data, src = read_named(p, prefer)
            if data:
                blob = data[: 256 * 1024]
                if src and src not in names:
                    names.append(src)
                break
    elif p.is_file():
        blob = p.read_bytes()[: 256 * 1024]
        names = [p.name]
        if blob[:2] == b"PK":
            try:
                with zipfile.ZipFile(p) as zf:
                    names = [n.replace("\\", "/") for n in zf.namelist()[:800]]
            except (zipfile.BadZipFile, OSError):
                pass
    rec = classify_blob(blob, names)
    rec["path"] = str(p)
    rec["name_hits"] = [n for n in names if any(h in n.lower() for h in NAME_HINTS)][:40]
    return rec


def _need(path: str | Path) -> Path:
    p = Path(path).expanduser()
    if not p.exists():
        print(f"[!] 不存在：{p}", file=sys.stderr)
        sys.exit(2)
    return p


def _write_case(report: dict[str, Any], args: argparse.Namespace, extra: dict[str, str] | None = None) -> Path | None:
    case = getattr(args, "case", "") or ""
    outp = getattr(args, "out", None)
    if not case and not outp:
        return None
    from scope_lib import evidence_root, write_probe_json

    out = write_probe_json(
        report,
        case=case,
        out=outp,
        case_subdir="crack_cheat",
        filename="surface.json",
    )
    dirs: list[Path] = []
    if case:
        dirs.append(evidence_root() / case / "测绘" / "crack_cheat" / "hooks")
    if outp:
        dirs.append(Path(outp).parent / "hooks")
    seen: set[str] = set()
    if extra:
        for hook_dir in dirs:
            key = str(hook_dir)
            if key in seen:
                continue
            seen.add(key)
            hook_dir.mkdir(parents=True, exist_ok=True)
            for name, text in extra.items():
                (hook_dir / name).write_text(text, encoding="utf-8")
    return out


def _load_dump_and_meta(root: Path) -> tuple[list[dict[str, str]], list[str], dict[str, Any]]:
    dump_bytes, _ = read_named(root, "dump.cs")
    if root.is_file() and root.suffix.lower() in {".cs", ".txt"} and dump_bytes is None:
        dump_bytes = root.read_bytes()
    meta_bytes, _ = read_named(root, "global-metadata.dat")
    if root.is_file() and "metadata" in root.name.lower() and meta_bytes is None:
        meta_bytes = root.read_bytes()
    meta = parse_il2cpp_metadata(meta_bytes) if meta_bytes else {"ok": False}
    dump_hits = parse_dump_cs(dump_bytes.decode("utf-8", "replace")) if dump_bytes else []
    names = list(meta.get("hook_names") or [])
    return dump_hits, names, meta


def cmd_drive(args: argparse.Namespace) -> dict[str, Any]:
    root = _need(args.path)
    triage = scan_path(root)
    dump_hits, names, meta = _load_dump_and_meta(root)
    targets = pick_hook_targets(dump_hits, names)
    scripts = render_frida(targets)
    level = hook_level(targets)
    if level == "none":
        level = triage.get("level") or "none"
        if meta.get("ok") and level == "none":
            level = "L1"
    report = {
        "ts": datetime.now(UTC).isoformat(),
        "cmd": "drive",
        "level": level,
        "triage": triage,
        "metadata": {k: meta[k] for k in ("ok", "version", "hook_names", "level", "reason") if k in meta},
        "dump_hits": dump_hits[:40],
        "hook_targets": targets[:40],
        "hooks_written": list(scripts),
        "playbook": "传承/客器破禁.md",
        "skill": "客器破禁",
        "next": "frida -U -f <包> -l 案卷/crack_cheat/hooks/il2cpp.js ；再用 replay 打结算口",
    }
    out = _write_case(report, args, scripts)
    print(json.dumps({"level": level, "hooks": len(targets), "out": str(out or "")}, ensure_ascii=False))
    return report


def cmd_meta(args: argparse.Namespace) -> dict[str, Any]:
    p = _need(args.path)
    data, src = read_named(p, "global-metadata.dat")
    if data is None and p.is_file() and not _is_zip_file(p):
        data = p.read_bytes()
        src = str(p)
    if data is None:
        rec = {
            "ok": False,
            "reason": "no-metadata",
            "ts": datetime.now(UTC).isoformat(),
            "cmd": "meta",
            "path": str(p),
            "source": src,
            "playbook": "传承/客器破禁.md",
        }
        out = _write_case(rec, args)
        print(json.dumps({"ok": False, "reason": "no-metadata", "out": str(out or "")}, ensure_ascii=False))
        return rec
    rec = parse_il2cpp_metadata(data)
    rec["ts"] = datetime.now(UTC).isoformat()
    rec["cmd"] = "meta"
    rec["path"] = str(p)
    rec["source"] = src
    rec["playbook"] = "传承/客器破禁.md"
    out = _write_case(rec, args)
    print(json.dumps({"ok": rec.get("ok"), "hooks": len(rec.get("hook_names") or []), "out": str(out or "")}, ensure_ascii=False))
    return rec


def cmd_hooks(args: argparse.Namespace) -> dict[str, Any]:
    root = _need(args.path)
    dump_hits, names, _meta = _load_dump_and_meta(root)
    targets = pick_hook_targets(dump_hits, names)
    scripts = render_frida(targets)
    report = {
        "ts": datetime.now(UTC).isoformat(),
        "cmd": "hooks",
        "level": hook_level(targets),
        "hook_targets": targets,
        "hooks_written": list(scripts),
        "playbook": "传承/客器破禁.md",
    }
    out = _write_case(report, args, scripts)
    print(json.dumps({"hooks": len(targets), "out": str(out or "")}, ensure_ascii=False))
    return report


def cmd_replay(args: argparse.Namespace) -> dict[str, Any]:
    from scope_lib import host_of, in_scope

    try:
        import requests

        requests.packages.urllib3.disable_warnings()  # type: ignore
    except ImportError:
        print("[!] pip install requests", file=sys.stderr)
        sys.exit(1)

    host = host_of(args.base)
    if not host or not in_scope(host):
        print(f"[!] 不在 scope：{host or args.base}", file=sys.stderr)
        sys.exit(2)
    base = args.base.rstrip("/")
    sess = requests.Session()
    sess.headers["User-Agent"] = "Mozilla/5.0 大爱仙尊-crack-cheat"
    for raw in args.header or []:
        if ":" in raw:
            k, v = raw.split(":", 1)
            sess.headers[k.strip()] = v.strip()
    body: dict[str, Any] = {}
    if args.body:
        body = json.loads(Path(args.body).read_text(encoding="utf-8"))
    flips = [x for x in (args.flip or []) if x]
    if not flips:
        flips = ["gold=99999", "score=99999", "win=true", "isWinner=true"]
    forged = apply_flips(body, flips)
    explicit_url = bool(args.url)
    paths = [args.url] if args.url else list(GAME_API)
    findings: list[dict[str, Any]] = []
    for p in paths:
        url = p if p.startswith("http") else urljoin(base + "/", p.lstrip("/"))
        try:
            a = sess.post(url, json=body, timeout=args.timeout, verify=False)
            b = sess.post(url, json=forged, timeout=args.timeout, verify=False)
        except Exception as exc:
            findings.append({"path": p, "error": str(exc)[:120]})
            continue
        level, reason = replay_verdict(
            a.status_code, b.status_code, a.content, b.content, size_ok=explicit_url
        )
        row = {
            "path": p,
            "base_status": a.status_code,
            "flip_status": b.status_code,
            "base_size": len(a.content),
            "flip_size": len(b.content),
            "reason": reason,
            "level": level,
        }
        findings.append(row)
        if level == "L2":
            print(f"  L2 replay {p} {a.status_code}→{b.status_code} {reason}")
            break
    level = "L2" if any(f.get("level") == "L2" for f in findings) else (
        "L1" if findings else "none"
    )
    report = {
        "ts": datetime.now(UTC).isoformat(),
        "cmd": "replay",
        "target": base,
        "level": level,
        "forged": forged,
        "findings": findings,
        "playbook": "传承/客器破禁.md",
        "next": "L2=结算口吃了客户端分/币/胜负。填对象矩阵写格。他人局/耗余额先问。",
    }
    out = _write_case(report, args)
    print(json.dumps({"level": level, "out": str(out or "")}, ensure_ascii=False))
    return report


def cmd_memscan(args: argparse.Namespace) -> dict[str, Any]:
    p = _need(args.dump)
    data = p.read_bytes()
    rec = scan_mem_values(data, value=args.int, text=args.str or "")
    rec.update({
        "ts": datetime.now(UTC).isoformat(),
        "cmd": "memscan",
        "path": str(p),
        "size": len(data),
        "playbook": "传承/客器破禁.md",
        "next": "地址只是 L1。改值后必须 replay/抓包证明服务器认。",
    })
    out = _write_case(rec, args)
    print(json.dumps({"int_hits": len(rec["int_hits"]), "str_hits": len(rec["str_hits"]), "out": str(out or "")}, ensure_ascii=False))
    return rec


def run(args: argparse.Namespace) -> dict[str, Any]:
    cmd = getattr(args, "cmd", "") or "drive"
    if cmd == "drive":
        return cmd_drive(args)
    if cmd == "meta":
        return cmd_meta(args)
    if cmd == "hooks":
        return cmd_hooks(args)
    if cmd == "replay":
        return cmd_replay(args)
    if cmd == "memscan":
        return cmd_memscan(args)
    print("[!] 未知子命令", file=sys.stderr)
    sys.exit(2)


def main() -> None:
    ap = argparse.ArgumentParser(description="大爱仙尊客户端破解/外挂作业链（授权内）")
    sub = ap.add_subparsers(dest="cmd")

    d = sub.add_parser("drive", help="本地样本一键出 hook")
    d.add_argument("--path", required=True)
    d.add_argument("--case", default="")
    d.add_argument("--out", type=Path, default=None)

    m = sub.add_parser("meta", help="解析 global-metadata.dat")
    m.add_argument("--path", required=True)
    m.add_argument("--case", default="")
    m.add_argument("--out", type=Path, default=None)

    h = sub.add_parser("hooks", help="从 dump.cs / metadata 出 Frida")
    h.add_argument("--path", required=True)
    h.add_argument("--case", default="")
    h.add_argument("--out", type=Path, default=None)

    r = sub.add_parser("replay", help="结算口改字段对照")
    r.add_argument("--base", "-u", required=True)
    r.add_argument("--url", default="", help="结算路径，默认扫短表")
    r.add_argument("--body", default="", help="JSON 基线文件")
    r.add_argument("--flip", action="append", default=[], help="gold=99999 或 player.gold=1，可重复")
    r.add_argument("--header", action="append", default=[], help="Name: value，可重复")
    r.add_argument("--case", default="")
    r.add_argument("--out", type=Path, default=None)
    r.add_argument("--timeout", type=int, default=8)

    s = sub.add_parser("memscan", help="内存转储扫值")
    s.add_argument("--dump", required=True)
    s.add_argument("--int", type=int, default=None)
    s.add_argument("--str", default="")
    s.add_argument("--case", default="")
    s.add_argument("--out", type=Path, default=None)

    args = ap.parse_args()
    if not args.cmd:
        ap.print_help()
        raise SystemExit(0)
    run(args)


if __name__ == "__main__":
    main()
