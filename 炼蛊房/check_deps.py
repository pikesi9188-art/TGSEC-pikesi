#!/usr/bin/env python3
"""检查炼蛊房在本机缺什么（Python 库 / 外门二进制）。

开源版：
  python3 炼蛊房/check_deps.py
工作区：
  python3 炼蛊房/check_deps.py
"""
from __future__ import annotations

import importlib
import shutil
import sys
from pathlib import Path

PY_NEED = (
    ("requests", "pip install requests", "多数 HTTP 探针"),
)
PY_OPT = (
    ("cryptography", "pip install cryptography", "部分 JWT / Next 链"),
    ("rarfile", "pip install rarfile", "解 rar 窃密包"),
    ("jwt", "pip install PyJWT", "少数票面脚本；本库多数自带解析"),
)
BINS = (
    ("nuclei", "https://github.com/projectdiscovery/nuclei/releases 或 brew install nuclei", "一日针匣 / 1day 模板"),
    ("sqlmap", "https://github.com/sqlmapproject/sqlmap.git （太大不进仓）", "无底洞 / sqlmap_kit"),
    ("ffuf", "https://github.com/ffuf/ffuf/releases 或 brew install ffuf", "目录/爆破"),
    ("jadx", "https://github.com/skylot/jadx/releases", "安器反编译"),
    ("frida", "pip install frida-tools", "客器破禁动态 hook"),
    ("java", "https://adoptium.net Temurin 17", "开棺 / 铜府 / 网关"),
    ("dotnet", "https://dotnet.microsoft.com （Il2CppDumper 用）", "出 dump.cs"),
    ("unar", "brew install unar 或 https://theunarchiver.com/command-line", "rar 包"),
    ("openssl", "系统自带或 brew install openssl", "证书/TLS"),
)
BIG_NOT_IN_REPO = (
    ("Il2CppDumper", "https://github.com/Perfare/Il2CppDumper/releases", "客器破禁出 dump.cs，需 .NET"),
    ("frida-il2cpp-bridge", "npm i frida-il2cpp-bridge", "按类名 hook；有 RVA 可不装"),
    ("nuclei-templates", "nuclei -update-templates", "一日针匣全量 CVE，体积大"),
    ("Ghidra", "https://github.com/NationalSecurityAgency/ghidra/releases", "逆骨深挖，可选"),
    ("空间眼 API", "自备 FOFA/Hunter Key；脚本在工作区 tools/space-search", "搜魂蛊证书/目录猎，开源版只留命令"),
    ("DeepAudit", "工作区 tools/deepaudit，开源版不带 vendor", "白盒审"),
    ("evasion-kit", "工作区 tools/evasion-kit", "隐鳞 WAF 变体"),
    ("Spring Gateway 杀伤链", "工作区 tools/spring-gateway-killchain + JDK17 + jasypt", "春府关窍全链"),
)


def _has_mod(name: str) -> bool:
    try:
        importlib.import_module(name)
        return True
    except Exception:
        return False


def main() -> int:
    print("== Python", sys.version.split()[0], "==")
    miss = 0
    print("\n[必须]")
    for name, how, why in PY_NEED:
        ok = _has_mod(name)
        miss += 0 if ok else 1
        print(f"  {'OK' if ok else '缺'}  {name:16}  {why}")
        if not ok:
            print(f"       装：{how}")
    print("\n[可选 Python]")
    for name, how, why in PY_OPT:
        ok = _has_mod(name)
        print(f"  {'OK' if ok else '无'}  {name:16}  {why}")
        if not ok:
            print(f"       装：{how}")
    print("\n[外门二进制] 太大不进仓，自己装 PATH")
    for name, how, why in BINS:
        hit = shutil.which(name)
        print(f"  {'OK' if hit else '无'}  {name:16}  {why}")
        if not hit:
            print(f"       装：{how}")
    print("\n[不进仓的大件]")
    for name, how, why in BIG_NOT_IN_REPO:
        print(f"  · {name}")
        print(f"    {why}")
        print(f"    {how}")
    here = Path(__file__).resolve().parent
    print("\n[本柜]")
    print(f"  脚本目录 {here}")
    print(f"  缺必须库 {miss} 个")
    print("  授权：开源版写 态度蛊.json；工作区走 授权范围")
    return 1 if miss else 0


if __name__ == "__main__":
    raise SystemExit(main())
