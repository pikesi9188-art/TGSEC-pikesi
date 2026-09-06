#!/usr/bin/env python3
"""授权主机应急响应检查（本机或已拿 shell 的 Linux）。

只采集：异常用户、启动项、计划任务、监听口、预加载、最近登录。
不清痕迹、不杀进程、不改密码。提权面仍走 linux_lpe_checker.py。
默认不跑 sudo -l（会卡住等密码）；需要时加 --sudo。
"""
from __future__ import annotations

import argparse
import json
import os
import pwd
import socket
import subprocess
import sys
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import write_probe_json  # noqa: E402
from wp_drop_lib import HOST_REL_DIRS, is_campaign_drop_name  # noqa: E402


def _run(cmd: list[str], timeout: int = 6) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, ((p.stdout or "") + (p.stderr or ""))
    except FileNotFoundError:
        return 127, ""
    except Exception as exc:
        return 1, f"[err] {exc}"


def _read(path: str, limit: int = 4000) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")[:limit]
    except Exception:
        return ""


def _list_dir(path: str, limit: int = 30) -> list[str]:
    try:
        names = sorted(p.name for p in Path(path).iterdir())
        return names[:limit]
    except Exception:
        return []


def collect(do_sudo: bool) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    users: list[dict[str, Any]] = []
    try:
        for ent in pwd.getpwall():
            if ent.pw_uid == 0 and ent.pw_name != "root":
                findings.append(
                    {
                        "family": "hidden-root",
                        "level": "L2",
                        "signal": "uid0-not-root",
                        "user": ent.pw_name,
                        "shell": ent.pw_shell,
                    }
                )
            if ent.pw_name.startswith(" ") or "$" in ent.pw_name:
                findings.append(
                    {
                        "family": "hidden-user",
                        "level": "L2",
                        "signal": "hidden-username",
                        "user": repr(ent.pw_name),
                        "uid": ent.pw_uid,
                    }
                )
            if ent.pw_uid >= 1000 or ent.pw_uid == 0:
                users.append(
                    {
                        "name": ent.pw_name,
                        "uid": ent.pw_uid,
                        "shell": ent.pw_shell,
                        "home": ent.pw_dir,
                    }
                )
    except Exception:
        pass

    preload = _read("/etc/ld.so.preload")
    if preload.strip():
        findings.append(
            {
                "family": "ld-preload",
                "level": "L2",
                "signal": "ld-so-preload",
                "preview": preload.strip()[:200],
            }
        )

    code, crontab = _run(["crontab", "-l"])
    if code == 0 and crontab.strip() and "no crontab" not in crontab.lower():
        findings.append({"family": "cron", "level": "L1", "signal": "user-crontab", "preview": crontab[:300]})

    cron_d = _list_dir("/etc/cron.d")
    if cron_d:
        findings.append({"family": "cron", "level": "L1", "signal": "cron-d", "files": cron_d})

    rc_local = _read("/etc/rc.local")
    if rc_local and any(x in rc_local for x in ("wget ", "curl ", "nc ", "bash -i", "/tmp/")):
        findings.append({"family": "rc-local", "level": "L2", "signal": "rc-local-suspicious", "preview": rc_local[:300]})

    keys = _read("/root/.ssh/authorized_keys") or _read(str(Path.home() / ".ssh" / "authorized_keys"))
    extra = [ln for ln in keys.splitlines() if ln.strip() and not ln.strip().startswith("#")] if keys else []
    if extra:
        findings.append({"family": "ssh-keys", "level": "L1", "signal": "authorized-keys", "count": len(extra)})

    code, listen = _run(["ss", "-lntup"])
    if code != 0 or not listen.strip():
        _, listen = _run(["netstat", "-lntup"])

    _, auth = _run(["last", "-n", "15"])
    sudo_txt = _read("/etc/sudoers")
    if do_sudo:
        _, sudo_l = _run(["sudo", "-n", "-l"], timeout=4)
        sudo_txt = (sudo_txt + "\n" + sudo_l)[:800]

    tmp_hits = []
    for p in Path("/tmp").glob("*.php"):
        tmp_hits.append(str(p))
        if len(tmp_hits) >= 8:
            break
    if tmp_hits:
        findings.append({"family": "tmp-web", "level": "L1", "signal": "tmp-php", "files": tmp_hits})

    drop_hits: list[str] = []
    roots = [Path("/var/www/html"), Path("/var/www/wordpress"), Path("/usr/share/nginx/html")]
    www = Path("/var/www")
    if www.is_dir():
        try:
            roots.extend(
                child for child in www.iterdir()
                if child.is_dir() and not child.is_symlink()
            )
        except OSError:
            pass
    drop_dirs: list[Path] = []
    for root in roots:
        for rel in HOST_REL_DIRS:
            drop_dirs.append(root / rel if rel else root)
    seen: set[str] = set()
    for d in drop_dirs:
        if len(drop_hits) >= 20 or not d.is_dir():
            continue
        try:
            for p in d.iterdir():
                if p.is_symlink() or not p.is_file():
                    continue
                if is_campaign_drop_name(p.name) and str(p) not in seen:
                    seen.add(str(p))
                    drop_hits.append(str(p))
                if len(drop_hits) >= 20:
                    break
        except OSError:
            continue
    if drop_hits:
        findings.append(
            {
                "family": "wp-drop",
                "level": "L2",
                "signal": "high-entropy-11char-php",
                "files": drop_hits,
                "note": "11位大小写混用 .php（排除 formatting.php）；见 WordPress高熵PHP马落点狩猎",
            }
        )

    return {
        "host": socket.gethostname(),
        "user": os.environ.get("USER") or "",
        "cwd": os.getcwd(),
        "users": users[:40],
        "listen_preview": listen[:1200],
        "last_preview": auth[:800],
        "sudo_preview": sudo_txt[:600],
        "findings": findings,
    }


def run(case: str, out: Path | None, do_sudo: bool) -> dict[str, Any]:
    data = collect(do_sudo)
    report: dict[str, Any] = {
        "ts": datetime.now(UTC).isoformat(),
        **data,
        "playbook": "传承/自我守护.md",
        "skill": "杀招/宿主验",
        "next": [
            "uid0 非 root / ld.so.preload → 先取证再处置，禁止直接删",
            "high-entropy-11char-php → 传承/坞壳落子猎.md；连马先问",
            "提权面另跑 linux_lpe_checker.py",
            "要清痕迹？本卡不做；用户说暂停则只留证据",
            "Windows 主机用 PCHunter/WES-NG，本探针是 Linux",
        ],
    }
    out_path = write_probe_json(
        report, case=case, out=out, case_subdir="host_ir", filename="ir.json"
    )
    print(
        json.dumps(
            {
                "findings": len(report.get("findings") or []),
                "users": len(report.get("users") or []),
                "out": str(out_path),
            },
            ensure_ascii=False,
        )
    )
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="授权主机应急响应检查")
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--sudo", action="store_true", help="另跑 sudo -n -l（默认不跑，防卡住）")
    args = ap.parse_args()
    run(args.case, args.out, args.sudo)


if __name__ == "__main__":
    main()
