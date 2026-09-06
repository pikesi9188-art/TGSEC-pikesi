#!/usr/bin/env python3
"""Payload 库检索 — 来自 72stack-sec（305 结构化 payload + 176 WAF/EDR 绕过）

用法：
  python3 炼蛊房/payload_lookup.py --list
  python3 炼蛊房/payload_lookup.py --type xss
  python3 炼蛊房/payload_lookup.py --type sqli
  python3 炼蛊房/payload_lookup.py --type waf-bypass
  python3 炼蛊房/payload_lookup.py --type rce
  python3 炼蛊房/payload_lookup.py --keyword "union select"
  python3 炼蛊房/payload_lookup.py --type ssrf --keyword "127.0.0.1"
  python3 炼蛊房/payload_lookup.py --tools --keyword "反弹shell"
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

SKILL_BASE = Path(__file__).resolve().parents[1] / "杀招" / "七十二层防"
PAYLOAD_BASE = SKILL_BASE / "references" / "payloader"
WEB_CAT = PAYLOAD_BASE / "by-category" / "web"
INTRANET_CAT = PAYLOAD_BASE / "by-category" / "intranet"
TOOLS_DIR = PAYLOAD_BASE / "tools"
WAF_FILE = PAYLOAD_BASE / "waf-bypass.md"

# payload 类型 → 对应文件名（支持模糊映射）
TYPE_MAP: dict[str, list[str]] = {
    "xss":          ["xss跨站脚本.md"],
    "sqli":         ["sql-nosql注入.md"],
    "sql":          ["sql-nosql注入.md"],
    "rce":          ["rce远程代码执行.md"],
    "ssrf":         ["ssrf服务端请求伪造.md"],
    "ssti":         ["ssti模板注入.md"],
    "xxe":          ["xxe实体注入.md"],
    "lfi":          ["lfi-rfi文件包含.md"],
    "rfi":          ["lfi-rfi文件包含.md"],
    "jwt":          ["jwt安全.md"],
    "csrf":         ["csrf跨站请求伪造.md"],
    "websocket":    ["websocket安全.md"],
    "redirect":     ["开放重定向.md"],
    "logic":        ["业务逻辑漏洞.md"],
    "file":         ["文件漏洞.md"],
    "framework":    ["框架漏洞.md"],
    "clickjacking": ["点击劫持.md"],
    "cache":        ["缓存与cdn安全.md"],
    "cdn":          ["缓存与cdn安全.md"],
    "auth":         ["认证漏洞.md"],
    "smuggling":    ["请求走私.md"],
    "cloud":        ["云安全漏洞.md"],
    "supply":       ["供应链攻击.md"],
    "proto":        ["原型链污染.md"],
    "api":          ["api安全.md"],
    "ai":           ["ai安全.md"],
    # 内网
    "lateral":      ["横向移动.md"],
    "privesc":      ["权限提升.md"],
    "persistence":  ["权限维持.md"],
    "tunnel":       ["隧道代理.md"],
    "domain":       ["域渗透攻击.md"],
    "adcs":         ["adcs攻击.md"],
    "exchange":     ["exchange攻击.md"],
    "cred":         ["凭证窃取.md"],
    "evasion":      ["免杀与规避.md"],
    # 工具
    "revshell":     ["反弹shell.md"],
    "web-tools":    ["web渗透.md"],
    "info":         ["信息收集.md"],
    "encode":       ["编码解码.md"],
    "password":     ["密码攻击.md"],
    "exploit":      ["漏洞利用.md"],
    "red":          ["红队工具.md"],
    "windows":      ["windows渗透.md"],
    "intranet-tools": ["内网渗透.md"],
    "cmd":          ["系统命令.md"],
    # 特殊
    "waf-bypass":   ["__WAF__"],
    "waf":          ["__WAF__"],
}


def _find_file(name: str) -> Path | None:
    for d in [WEB_CAT, INTRANET_CAT, TOOLS_DIR]:
        p = d / name
        if p.exists():
            return p
    return None


def _search_md(path: Path, keyword: str | None) -> str:
    text = path.read_text(encoding="utf-8")
    if not keyword:
        return text
    kw = keyword.lower()
    lines = text.splitlines()
    out: list[str] = []
    i = 0
    while i < len(lines):
        if kw in lines[i].lower():
            start = max(0, i - 1)
            end = min(len(lines), i + 6)
            out.extend(lines[start:end])
            out.append("---")
            i = end
        else:
            i += 1
    return "\n".join(out) if out else f"[payload_lookup] 关键词 '{keyword}' 未命中"


def cmd_list() -> None:
    print("\n[payload_lookup] 可用 payload 类型\n")
    print("── Web ──")
    for f in sorted(WEB_CAT.glob("*.md")):
        size = f.stat().st_size
        print(f"  {size:7d}B  {f.name}")
    print("\n── 内网 ──")
    for f in sorted(INTRANET_CAT.glob("*.md")):
        size = f.stat().st_size
        print(f"  {size:7d}B  {f.name}")
    print("\n── 工具命令 ──")
    for f in sorted(TOOLS_DIR.glob("*.md")):
        size = f.stat().st_size
        print(f"  {size:7d}B  {f.name}")
    print("\n── WAF/EDR 绕过 ──")
    if WAF_FILE.exists():
        size = WAF_FILE.stat().st_size
        lines = len(WAF_FILE.read_text(encoding="utf-8").splitlines())
        print(f"  {size:7d}B  waf-bypass.md ({lines} 行)")
    print("\n常用 --type 别名:")
    for alias in sorted(TYPE_MAP):
        print(f"  {alias}")


def cmd_lookup(type_: str, keyword: str | None) -> None:
    files = TYPE_MAP.get(type_.lower())
    if not files:
        # 尝试直接文件名匹配
        direct = _find_file(type_)
        if direct:
            print(f"\n[payload_lookup] {direct.name}\n{'='*60}")
            print(_search_md(direct, keyword))
            return
        print(f"[payload_lookup] 未知类型 '{type_}'，用 --list 查看所有可用类型")
        sys.exit(1)

    for fname in files:
        if fname == "__WAF__":
            if not WAF_FILE.exists():
                print(f"[payload_lookup] 找不到 {WAF_FILE}")
                continue
            print(f"\n[payload_lookup] waf-bypass.md（176 个绕过 payload）\n{'='*60}")
            print(_search_md(WAF_FILE, keyword))
        else:
            path = _find_file(fname)
            if not path:
                print(f"[payload_lookup] 找不到文件: {fname}")
                continue
            print(f"\n[payload_lookup] {path.name}\n{'='*60}")
            print(_search_md(path, keyword))


def cmd_keyword_global(keyword: str) -> None:
    """在所有 payload 文件里全局搜索关键词。"""
    kw = keyword.lower()
    all_files = (
        list(WEB_CAT.glob("*.md"))
        + list(INTRANET_CAT.glob("*.md"))
        + list(TOOLS_DIR.glob("*.md"))
        + ([WAF_FILE] if WAF_FILE.exists() else [])
    )
    hits = 0
    for path in all_files:
        text = path.read_text(encoding="utf-8")
        if kw in text.lower():
            count = text.lower().count(kw)
            print(f"  [{count:3d} 处]  {path.name}")
            hits += 1
    if hits == 0:
        print(f"[payload_lookup] 关键词 '{keyword}' 在所有 payload 文件中未命中")
    else:
        print(f"\n共 {hits} 个文件命中，用 --type <类型> --keyword <词> 查看详情")


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Payload 库检索（72stack-sec · 305 结构化 + 176 WAF绕过）"
    )
    ap.add_argument("--list", action="store_true", help="列出所有可用 payload 类型")
    ap.add_argument("--type", "-t", help="指定 payload 类型（见 --list）")
    ap.add_argument("--keyword", "-k", help="在指定类型或全库内搜索关键词")
    ap.add_argument("--tools", action="store_true", help="只搜索工具命令库")
    args = ap.parse_args()

    if not PAYLOAD_BASE.exists():
        sys.exit(f"[payload_lookup] 找不到 payload 库：{PAYLOAD_BASE}\n请确认 72stack-sec 已克隆")

    if args.list:
        cmd_list()
        return

    if args.tools:
        if args.keyword:
            cmd_keyword_global(args.keyword)
        else:
            for f in sorted(TOOLS_DIR.glob("*.md")):
                print(f"  {f.name}")
        return

    if args.type:
        cmd_lookup(args.type, args.keyword)
        return

    if args.keyword:
        print(f"\n[payload_lookup] 全库搜索: '{args.keyword}'\n")
        cmd_keyword_global(args.keyword)
        return

    ap.print_help()


if __name__ == "__main__":
    main()
