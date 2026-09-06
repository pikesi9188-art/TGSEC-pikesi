#!/usr/bin/env python3
"""gRPC / Spring Boot 非 REST 端点探针。

适用于博彩站的 Spring Boot + gRPC 微服务（如 ss.qzino.com 类型），
这类后台不接受 HTTP/REST，用普通 curl/requests 必然失败。

依赖：
  pip3 install grpcio grpcio-reflection
  brew install grpcurl  # 或用二进制（见下）

示例:
  python3 炼蛊房/grpc_probe.py doctor
  python3 炼蛊房/grpc_probe.py detect --target ss.qzino.com:443 --case <案卷>
  python3 炼蛊房/grpc_probe.py list --target ss.qzino.com:443 --case <案卷>
  python3 炼蛊房/grpc_probe.py call --target ss.qzino.com:443 \
    --service helloworld.Greeter --method SayHello \
    --data '{"name":"test"}' --case <案卷>
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, UTC
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
OPS = Path(__file__).resolve().parent
ARSENAL_BIN = ENGINE / "tools" / "arsenal" / "bin"
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import in_scope  # noqa: E402


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def case_dir(case: str) -> Path:
    d = ENGINE / "案卷" / case / "测绘" / "grpc"
    d.mkdir(parents=True, exist_ok=True)
    return d


def find_grpcurl() -> str | None:
    for candidate in (
        str(ARSENAL_BIN / "grpcurl"),
        shutil.which("grpcurl") or "",
        "/usr/local/bin/grpcurl",
        "/opt/homebrew/bin/grpcurl",
    ):
        if candidate and Path(candidate).is_file() and os.access(candidate, os.X_OK):
            return candidate
    return None


def ensure_scope(target: str) -> None:
    host = target.split(":")[0]
    if host in ("127.0.0.1", "localhost", "::1"):
        return
    if not in_scope(host):
        raise SystemExit(f"[scope] {host} 不在授权范围")


def run_grpcurl(args_extra: list[str], timeout: int = 30) -> tuple[int, str]:
    grpcurl = find_grpcurl()
    if not grpcurl:
        return 127, "grpcurl not found — run: bash 炼蛊房/install_grpcurl.sh"
    cmd = [grpcurl] + args_extra
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    except Exception as exc:
        return 1, str(exc)


def detect_grpc(target: str) -> dict:
    """尝试检测目标是否暴露 gRPC（含 reflection）。"""
    result = {
        "ts": _now(),
        "target": target,
        "grpc_detected": False,
        "reflection": False,
        "http2": False,
        "indicators": [],
    }

    # 1) grpcurl 快速探针
    rc, out = run_grpcurl(["-plaintext", target, "list"] if ":" in target and not target.endswith(":443")
                          else ["-insecure", target, "list"])
    if rc == 0:
        result["grpc_detected"] = True
        result["reflection"] = True
        result["indicators"].append("grpcurl list OK — reflection enabled")
    elif "failed to connect" in out.lower() or "refused" in out.lower():
        result["indicators"].append("connection refused")
    elif "not implemented" in out.lower() or "unknown service" in out.lower():
        result["grpc_detected"] = True
        result["indicators"].append("gRPC detected but reflection disabled")

    # 2) HTTP/2 探测（curl）
    curl = shutil.which("curl")
    if curl:
        r = subprocess.run(
            [curl, "--http2-prior-knowledge", "-s", "-o", "/dev/null", "-w", "%{http_code}",
             f"https://{target}/"],
            capture_output=True, text=True, timeout=10,
        )
        if r.stdout in ("200", "400", "404", "405"):
            result["http2"] = True
            result["indicators"].append(f"HTTP/2 response: {r.stdout}")

    # 3) TLS ALPN 探测
    host, port = (target.split(":") + ["443"])[:2]
    r2 = subprocess.run(
        ["openssl", "s_client", "-connect", f"{host}:{port}", "-alpn", "h2",
         "-brief", "-timeout", "3"],
        input="", capture_output=True, text=True, timeout=8,
    )
    if "h2" in (r2.stdout + r2.stderr):
        result["http2"] = True
        result["indicators"].append("TLS ALPN h2 negotiated")

    return result


def cmd_doctor(_: argparse.Namespace) -> int:
    grpcurl = find_grpcurl()
    print(f"[{'ok' if grpcurl else 'missing'}] grpcurl: {grpcurl or '-'}")
    if not grpcurl:
        print("  hint: bash 炼蛊房/install_grpcurl.sh")
    try:
        import grpc  # type: ignore
        print(f"[ok] grpcio: {grpc.__version__}")
    except ImportError:
        print("[missing] grpcio: pip3 install grpcio grpcio-reflection")
    print("[ok] grpc_probe ready")
    return 0


def cmd_detect(args: argparse.Namespace) -> int:
    ensure_scope(args.target)
    result = detect_grpc(args.target)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if args.case:
        out = case_dir(args.case) / "detect.json"
        out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"[*] evidence → {out}")
    print(f"\n[verdict] gRPC={'yes' if result['grpc_detected'] else 'no'} "
          f"reflection={'yes' if result['reflection'] else 'no'} "
          f"HTTP/2={'yes' if result['http2'] else 'no'}")
    return 0 if result["grpc_detected"] else 1


def cmd_list(args: argparse.Namespace) -> int:
    """列举所有 gRPC 服务（需要 reflection 开启）。"""
    ensure_scope(args.target)
    flags = ["-insecure"] if args.insecure else ["-plaintext"]
    rc, out = run_grpcurl(flags + [args.target, "list"])
    print(out)
    if rc != 0:
        print("[!] reflection may be disabled — try cmd_describe or known service name")
        return rc
    services = [line.strip() for line in out.splitlines() if line.strip()]
    if args.case:
        out_json = case_dir(args.case) / "services.json"
        out_json.write_text(
            json.dumps({"ts": _now(), "target": args.target, "services": services},
                       ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"[*] {len(services)} services → {out_json}")
    # 对每个 service 列举 methods
    for svc in services[:20]:
        print(f"\n  --- {svc} ---", flush=True)
        _, method_out = run_grpcurl(flags + [args.target, "describe", svc])
        print(method_out[:500])
    return 0


def cmd_call(args: argparse.Namespace) -> int:
    """调用单个 gRPC 方法。"""
    ensure_scope(args.target)
    flags = ["-insecure"] if args.insecure else ["-plaintext"]
    grpc_method = f"{args.service}/{args.method}"
    data_args = ["-d", args.data] if args.data else []
    header_args = []
    if args.headers:
        for h in args.headers:
            header_args += ["-H", h]
    rc, out = run_grpcurl(flags + header_args + data_args + [args.target, grpc_method])
    print(out)
    if args.case:
        result = {"ts": _now(), "target": args.target, "method": grpc_method,
                  "data": args.data, "rc": rc, "output": out}
        case_dir(args.case) / f"call_{args.method}.json"
        (case_dir(args.case) / f"call_{args.method}.json").write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return rc


def main() -> int:
    p = argparse.ArgumentParser(description="gRPC / Spring Boot 端点探针")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("doctor")
    d.set_defaults(func=cmd_doctor)

    det = sub.add_parser("detect", help="检测目标是否暴露 gRPC")
    det.add_argument("--target", required=True, help="host:port")
    det.add_argument("--case", default="")
    det.set_defaults(func=cmd_detect)

    ls = sub.add_parser("list", help="列举 gRPC 服务（需 reflection）")
    ls.add_argument("--target", required=True)
    ls.add_argument("--insecure", action="store_true", default=True)
    ls.add_argument("--case", default="")
    ls.set_defaults(func=cmd_list)

    ca = sub.add_parser("call", help="调用 gRPC 方法")
    ca.add_argument("--target", required=True)
    ca.add_argument("--service", required=True, help="服务全名，如 helloworld.Greeter")
    ca.add_argument("--method", required=True, help="方法名，如 SayHello")
    ca.add_argument("--data", default="", help='JSON body，如 \'{"name":"test"}\'')
    ca.add_argument("--headers", nargs="*", help="额外 header：Authorization: Bearer xxx")
    ca.add_argument("--insecure", action="store_true", default=True)
    ca.add_argument("--case", default="")
    ca.set_defaults(func=cmd_call)

    args = p.parse_args()
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
