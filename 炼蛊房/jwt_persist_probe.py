#!/usr/bin/env python3
"""改密后旧 JWT 是否仍活（admin-backdoor-persistence）。不改原密。

  python3 炼蛊房/jwt_persist_probe.py drive --url https://授权/api/me --token '<旧票>' --case <案>
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

try:
    import requests

    requests.packages.urllib3.disable_warnings()  # type: ignore
except ImportError:
    print("[!] pip install requests", file=sys.stderr)
    sys.exit(1)

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from jwt_forge_probe import split_jwt  # noqa: E402
from scope_lib import host_of, in_scope, write_probe_json  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=("drive",))
    ap.add_argument("--url", required=True)
    ap.add_argument("--token", required=True)
    ap.add_argument("--case", default="")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    host = host_of(args.url)
    if not host or not in_scope(host):
        print(f"[!] 不在 scope：{host}", file=sys.stderr)
        raise SystemExit(2)
    try:
        header, payload, _ = split_jwt(args.token)
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"[!] 不是 JWT：{exc}", file=sys.stderr)
        raise SystemExit(2)
    try:
        r = requests.get(args.url, headers={"Authorization": f"Bearer {args.token}"}, timeout=10, verify=False)
        status, text = r.status_code, (r.text or "")[:300]
    except Exception as exc:
        status, text = 0, str(exc)[:80]
    alive = status == 200 and ("user" in text.lower() or "role" in text.lower() or "{" in text)
    rec = {
        "url": args.url,
        "status": status,
        "alive": alive,
        "alg": header.get("alg"),
        "iat": payload.get("iat"),
        "exp": payload.get("exp"),
        "level": "L2" if alive else "L1",
        "ts": datetime.now(UTC).isoformat(),
        "skill": "死票还活",
        "next": "L2=改密后旧票仍 200。不要默认改超管密。",
        "snip": text,
    }
    out = write_probe_json(rec, case=args.case, out=args.out, case_subdir="jwt_persist", filename="surface.json")
    print(json.dumps({"level": rec["level"], "alive": alive, "out": str(out)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
