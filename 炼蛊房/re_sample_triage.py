#!/usr/bin/env python3
"""大爱仙尊样本分诊：认族 → 专卡。只读本地文件，不联网。

先看魔数和包内文件名，再扫短字符串。输出 JSON：kind / family / skill / next。
不要对着未知样本先开 IDA。网站案能走 JS/APK 情报就不要先开通用逆向。

示例:
  python3 炼蛊房/re_sample_triage.py --path ./app.apk --case <案>
  python3 炼蛊房/re_sample_triage.py --path ./main.js
  python3 炼蛊房/re_sample_triage.py --self-test
"""
from __future__ import annotations

import argparse
import json
import sys
import zipfile
from pathlib import Path
from typing import Any

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))

HEAD = 256 * 1024
STRING_WINDOW = 64 * 1024


def _ascii_strings(data: bytes, min_len: int = 6) -> str:
    out: list[str] = []
    buf: list[int] = []
    for b in data:
        if 32 <= b < 127:
            buf.append(b)
            continue
        if len(buf) >= min_len:
            out.append(bytes(buf).decode("ascii", errors="ignore"))
        buf = []
    if len(buf) >= min_len:
        out.append(bytes(buf).decode("ascii", errors="ignore"))
    return "\n".join(out)


def _zip_names(path: Path) -> list[str]:
    try:
        with zipfile.ZipFile(path) as zf:
            return [n.replace("\\", "/") for n in zf.namelist()[:400]]
    except (zipfile.BadZipFile, OSError):
        return []


def sniff_magic(data: bytes) -> list[str]:
    tags: list[str] = []
    if data[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        tags.append("zip")
    if data[:4] == b"\x7fELF":
        tags.append("elf")
    if data[:2] == b"MZ":
        tags.append("pe")
    if data[:4] in (
        b"\xca\xfe\xba\xbe",
        b"\xcf\xfa\xed\xfe",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xce",
        b"\xfe\xed\xfa\xcf",
    ):
        tags.append("macho")
    if data[:4] == b"\x00asm":
        tags.append("wasm")
    if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
        tags.append("pcap")
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        tags.append("pcapng")
    if data[:6] == b"V1MMWX":
        tags.append("wxapkg")
    elif len(data) >= 18 and data[0] == 0xBE and data[13:17] == b"\x00\x00\x00\x00":
        tags.append("wxapkg")
    if data[:4] == b"CRX3" or data[:4] == b"Cr24":
        tags.append("crx")
    return tags


def classify(path: Path, *, data: bytes | None = None, names: list[str] | None = None) -> dict[str, Any]:
    p = Path(path)
    suffix = p.suffix.lower()
    name_l = p.name.lower()
    blob = data if data is not None else b""
    if data is None and p.is_file():
        with p.open("rb") as fh:
            blob = fh.read(HEAD)
    tags = sniff_magic(blob)
    text = _ascii_strings(blob[:STRING_WINDOW]).lower()
    zip_names = names if names is not None else (_zip_names(p) if "zip" in tags and p.is_file() else [])
    zip_l = " ".join(zip_names).lower()

    signals: list[str] = list(tags)
    kind = "unknown"
    family = ""
    skill = "reverse-engineering"
    note = "未认族，先开总路由再分诊"
    next_cmds: list[str] = [
        f'python3 炼蛊房/reverse_skill_route.py --hint "{p.name}"',
    ]

    def hit(k: str, fam: str, sk: str, n: str, cmds: list[str], *extra: str) -> None:
        nonlocal kind, family, skill, note, next_cmds
        kind, family, skill, note = k, fam, sk, n
        next_cmds = cmds
        signals.extend(extra)

    # 扩展名先钉，避免把 .js 当 unknown
    if suffix in {".apk", ".xapk", ".aab"} or "androidmanifest.xml" in zip_l or "classes.dex" in zip_l:
        hit(
            "apk",
            "android",
            "apk-recon",
            "先情报后深挖，完整反编译再 apk-reverse",
            [
                f"python3 炼蛊房/apk_recon.py extract --apk {p} --case <案>",
                "python3 炼蛊房/apk_recon.py doctor",
            ],
            "manifest/dex",
        )
        if any(x in zip_l for x in ("libtcx", "libwallet", "libtoken", "wallet_core")):
            family = "wallet"
            skill = "wallet-core-reverse"
            note = "钱包核心库，Java 层不算结案"
            next_cmds.append("python3 炼蛊房/apk_recon.py strings --apk %s --case <案>" % p)
            signals.append("wallet-so")
        if any(x in zip_l for x in ("il2cpp", "unityplayer", "global-metadata.dat", "gameassembly")):
            family = family or "unity-game"
            note = "Unity/IL2CPP APK：先 apk-recon 抽包，再 client-crack-cheat"
            next_cmds.append(
                f"python3 炼蛊房/client_crack_cheat_probe.py drive --path {p} --case <案>"
            )
            signals.append("unity-il2cpp")
    elif suffix == ".ipa" or "payload/" in zip_l:
        hit(
            "ipa",
            "ios",
            "ios-pentest",
            "应用面走 ios-pentest；内核/固件另开 ios-research",
            [f"file {p}", "不要把 IPA 当 macOS .app"],
            "payload",
        )
    elif suffix in {".crx", ".xpi"} or "crx" in tags or (
        "manifest.json" in zip_l and any(x in zip_l for x in ("background", "service_worker", "content_scripts"))
    ):
        hit(
            "crx",
            "extension",
            "browser-extension-reverse",
            "先读 manifest 权限面，不要当网页 JS",
            [f"unzip -l {p} | head", "读 manifest.json"],
            "extension-manifest",
        )
    elif suffix == ".wxapkg" or "wxapkg" in tags or name_l.endswith(".wxapkg"):
        hit(
            "wxapkg",
            "wxmini",
            "wxmini-static-audit",
            "Mac V1MMWX 先 wxapkg-mac-decrypt",
            [f"python3 炼蛊房/wxmini_static_probe.py --help"],
            "wxapkg",
        )
    elif suffix in {".pcap", ".pcapng", ".cap"} or "pcap" in tags or "pcapng" in tags:
        hit(
            "pcap",
            "protocol",
            "protocol-reverse",
            "先出消息类型表，禁止只贴 hex",
            [f"tshark -r {p} -T fields -e frame.number -e ip.src -e tcp.len | head"],
            "pcap",
        )
    elif "wasm" in tags or suffix == ".wasm":
        sk = "js-reverse"
        n = "标准 WASM：先导入表/桥，再反编译"
        if "goencrypt" in text or "tg" in name_l:
            sk = "tg-cloud-panel"
            n = "goEncrypt / 掩码票走 TG 云控第四族，禁止先拆 WASM"
        hit("wasm", "wasm", sk, n, [f'python3 炼蛊房/reverse_skill_route.py --hint "wasm {p.name}"'], "wasm")
    elif suffix in {".js", ".mjs", ".cjs", ".map"} or b"webpackChunk" in blob[:STRING_WINDOW] or b"sourceMappingURL" in blob[:STRING_WINDOW]:
        sk = "js-reverse"
        n = "先 hunt 密钥/.map，盘口国密再切 spa-protocol-reverse"
        if b"js-websocket" in blob[:STRING_WINDOW] or b"clientapi" in blob[:STRING_WINDOW]:
            sk = "spa-protocol-reverse"
            n = "js-websocket / 国密 clientapi，不要当普通签名"
        if b"jsvmp" in blob[:STRING_WINDOW] or (b"switch" in blob[:4096] and b"opcode" in blob[:STRING_WINDOW]):
            sk = "dsl-vm-reverse"
            n = "JS 自定义 VM：先 dispatcher，禁止盲补环境"
        hit(
            "js",
            "frontend",
            sk,
            n,
            [
                f"python3 炼蛊房/js_secret_hunter.py file --path {p} --case <案>",
                "python3 炼蛊房/js_secret_hunter.py doctor",
            ],
            "js-bundle",
        )
    elif "elf" in tags or suffix in {".so", ".elf"}:
        fam = "native"
        sk = "ghidra-reverse"
        n = "无 IDA 用 Ghidra；有炸点再 binary-pwn"
        cmds = [
            f"file {p}",
            f'strings {p} | rg -i "go.buildid|pclntab|jni_onload|rust_begin"',
        ]
        if "go.buildid" in text or "runtime.main" in text or "pclntab" in text:
            fam, sk, n = "go", "go-rust-reverse", "先恢复函数名，禁止对着 fcn.xxxx 硬读"
            signals.append("go")
        elif "rust_begin_unwind" in text or "rust_panic" in text:
            fam, sk, n = "rust", "go-rust-reverse", "先 panic/crate 路径字符串，再回溯泛型"
            signals.append("rust")
        if suffix == ".so" or "jni_onload" in text or "lib/" in name_l:
            if fam == "native":
                n = "JNI/so：加密 so 必须 dump 后再下结论"
                cmds = [f"file {p}", "strings 看 .init / JNI_OnLoad；壳 so 先 MemDumper"]
            signals.append("jni-so")
        hit("elf", fam, sk, n, cmds, *signals)
    elif "pe" in tags or suffix in {".exe", ".dll", ".sys"}:
        fam, sk, n = "windows", "ida-reverse", "PE/壳先认族；.NET 切 dotnet-reverse"
        if "mscoree" in text or b"BSJB" in blob[:4096] or suffix == ".dll" and "system." in text:
            fam, sk, n = "dotnet", "dotnet-reverse", ".NET 用 dnSpy/ILSpy，不要当原生 PE"
            signals.append("dotnet")
        if any(
            x in text or x in name_l
            for x in ("il2cpp", "gameassembly", "unityplayer", "easyanticheat", "battleye")
        ):
            fam, sk, n = "game-client", "client-crack-cheat", "游戏客户端先认引擎/反作弊，再打服务端是否信客户端"
            signals.append("game-client")
        hit("pe", fam, sk, n, [f"file {p}", "which detect-it-easy || echo 先看壳再下 IDA"], *signals)
    elif "macho" in tags or suffix in {".dylib", ".app"}:
        if "iphoneos" in text or "uikit" in text:
            hit("macho", "ios", "ios-pentest", "iOS Mach-O，不要当 macOS 桌面 App", [f"file {p}", "codesign -dv --verbose=4"], "ios-sdk")
        else:
            hit("macho", "macos", "macos-reverse", "先 codesign / otool，再反编译", [f"file {p}", f"codesign -dv --verbose=4 {p} 2>&1 | head", f"otool -L {p} | head"], "macos")
    elif suffix in {".bin", ".img", ".fw"} and len(blob) > 4096:
        hit("firmware", "firmware", "firmware-pentest", "固件先认分区，网站案降权", [f"file {p}", "binwalk -e 只在授权样本上"], "firmware")

    # 钱包 so 单独再抬一次（非 apk zip）
    if kind == "elf" and any(x in name_l for x in ("libtcx", "libwallet", "libtoken")):
        family = "wallet"
        skill = "wallet-core-reverse"
        note = "钱包核心 so，先 apk-recon 抽符号再进 JNI"
        signals.append("wallet-so")

    rec = {
        "path": str(p),
        "name": p.name,
        "kind": kind,
        "family": family,
        "skill": skill,
        "note": note,
        "signals": sorted(set(signals)),
        "next": next_cmds,
        "playbook": "传承/逆骨.md",
    }
    return rec


SELF_CASES: list[tuple[str, bytes, list[str], str, str]] = [
    ("app.apk", b"PK\x03\x04" + b"\x00" * 32, ["AndroidManifest.xml", "classes.dex", "lib/arm64-v8a/libc++.so"], "apk", "apk-recon"),
    ("wallet.apk", b"PK\x03\x04" + b"\x00" * 32, ["AndroidManifest.xml", "classes.dex", "lib/arm64-v8a/libtcx.so"], "apk", "wallet-core-reverse"),
    ("game.ipa", b"PK\x03\x04" + b"\x00" * 16, ["Payload/Foo.app/Info.plist"], "ipa", "ios-pentest"),
    ("ext.crx", b"PK\x03\x04" + b"\x00" * 16, ["manifest.json", "background.js", "content_scripts/x.js"], "crx", "browser-extension-reverse"),
    ("main.wasm", b"\x00asm" + b"\x01\x00\x00\x00", [], "wasm", "js-reverse"),
    ("bundle.js", b"window.webpackChunk=window.webpackChunk||[];sourceMappingURL=app.js.map\n", [], "js", "js-reverse"),
    ("ws.js", b'handshake type:"js-websocket" protoVersion\n', [], "js", "spa-protocol-reverse"),
    ("mini.wxapkg", b"V1MMWX" + b"\x00" * 20, [], "wxapkg", "wxmini-static-audit"),
    ("cap.pcap", b"\xd4\xc3\xb2\xa1" + b"\x00" * 20, [], "pcap", "protocol-reverse"),
    ("panel", b"\x7fELF" + b"\x00" * 16 + b"go.buildid\x00runtime.main\x00pclntab", [], "elf", "go-rust-reverse"),
    ("svc.exe", b"MZ" + b"\x00" * 60 + b"mscoree.dll System.Runtime", [], "pe", "dotnet-reverse"),
    ("GameAssembly.dll", b"MZ" + b"\x00" * 40 + b"il2cpp_runtime\x00UnityPlayer", [], "pe", "client-crack-cheat"),
]


def run_self_test() -> list[str]:
    fails: list[str] = []
    for name, blob, names, expect_kind, expect_skill in SELF_CASES:
        rec = classify(Path(name), data=blob, names=names)
        if rec["kind"] != expect_kind or rec["skill"] != expect_skill:
            fails.append(
                f"{name}: kind={rec['kind']} skill={rec['skill']} expect {expect_kind}/{expect_skill}"
            )
    return fails


def main() -> int:
    ap = argparse.ArgumentParser(description="大爱仙尊样本分诊：认族 → 专卡（只读本地）")
    ap.add_argument("--path", default="", help="本地样本路径")
    ap.add_argument("--case", default="", help="案卷名，写入 案卷/re_triage/")
    ap.add_argument("--json", action="store_true", help="只打 JSON")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        fails = run_self_test()
        if fails:
            for f in fails:
                print(f"FAIL {f}")
            return 1
        print(f"self-test ok  {len(SELF_CASES)} cases")
        return 0

    if not args.path:
        ap.error("需要 --path 或 --self-test")
    target = Path(args.path).expanduser()
    if not target.exists():
        print(f"[err] 文件不存在: {target}", file=sys.stderr)
        return 2

    rec = classify(target)
    if args.case:
        from scope_lib import write_probe_json  # 延迟导入，self-test 不碰案卷

        out = write_probe_json(
            rec,
            case=args.case,
            case_subdir="re_triage",
            filename="sample_triage.json",
        )
        rec["out"] = str(out)

    if args.json or args.case:
        print(json.dumps(rec, ensure_ascii=False, indent=2))
    else:
        print(f"KIND    {rec['kind']}")
        print(f"FAMILY  {rec['family'] or '-'}")
        print(f"SKILL   {rec['skill']}")
        print(f"NOTE    {rec['note']}")
        print(f"SIGNALS {', '.join(rec['signals']) or '-'}")
        print("NEXT")
        for c in rec["next"]:
            print(f"  {c}")
        print(f"PLAYBOOK {rec['playbook']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
