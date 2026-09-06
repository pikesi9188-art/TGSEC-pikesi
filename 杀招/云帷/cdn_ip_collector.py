#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cdn_ip_collector.py — CDN 厂商 IP 段深度收集器 (8 源并发 · v5.0)
================================================================
源自 SKILL.md §9.3 / §13.3「深度IP段收集 (8源并发)」。

8 个数据源并发拉取, 覆盖 51 家 CDN 厂商:
    1. Cloudflare ips-v4/v6           — 官方, 最准
    2. AWS CloudFront JSON            — 官方, 最全
    3. Fastly public-ip-list          — 官方
    4. Azure ServiceTags              — 官方 FrontDoor/CDN
    5. GCP Cloud IP Ranges            — 官方 (Google Cloud CDN)
    6. bgpview.io ASN                 — 第三方, 含历史, 覆盖全部 ASN
    7. RIPE Stat API                  — 权威当前 BGP, 覆盖全部 ASN
    8. RADB whois                     — 权威路由注册, 覆盖全部 ASN

输出格式 (与 cdn_ranges.py load_online_full 兼容):
    {
      "meta": {"fetched_at": ..., "sources": {...}, "totals": {...}},
      "vendors": {
        "Cloudflare": {"v4": ["1.2.3.0/24", ...], "v6": [...]},
        ...
      }
    }

用法:
    python cdn_ip_collector.py                       # 全量拉取 8 源
    python cdn_ip_collector.py --vendor Cloudflare,"阿里云 CDN"
    python cdn_ip_collector.py --output cdn_ranges_full.json
    python cdn_ip_collector.py --workers 16
    python cdn_ip_collector.py --merge > all_cdn_ranges.txt
    python cdn_ip_collector.py --load                # 仅加载, 不重新拉取

依赖:
    - requests (HTTP)
    - 标准库: ipaddress / json / concurrent.futures / subprocess
    - 可选: whois 命令 (RADB 源用, 缺失则跳过该源)
    - 复用 cdn_ranges.py 的 CDN_DATA (厂商+ASN 列表)

可被 cdn_tracer.py / cdn_ranges.py 联动:
    cdn_ranges.py --load-full <output>   # 加载本脚本输出
"""
import argparse
import concurrent.futures
import ipaddress
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# 复用同目录的 cdn_ranges 模块 (静态库 + 厂商/ASN 列表)
try:
    from cdn_ranges import CDN_DATA, _is_valid_cidr  # type: ignore
except ImportError:
    # 允许直接以文件路径执行 (添加当前目录到 sys.path)
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    try:
        from cdn_ranges import CDN_DATA, _is_valid_cidr  # type: ignore
    except ImportError:
        print("[致命错误] 无法导入 cdn_ranges.py, 请确保与本脚本在同一目录", file=sys.stderr)
        CDN_DATA = {}  # type: ignore
        def _is_valid_cidr(s: str) -> bool:  # type: ignore
            try:
                ipaddress.ip_network(s.strip(), strict=False)
                return True
            except Exception:
                return False

import requests

# ======================================================================
# 全局配置
# ======================================================================
USER_AGENT = "cdn_ip_collector/5.0 (+https://github.com/skills/cdn-origin-tracing)"
DEFAULT_TIMEOUT = 30
DEFAULT_OUTPUT = "cdn_ranges_full.json"

# 厂商 -> ASN 列表 (从 CDN_DATA 提取, 用于按 ASN 拉取)
def _vendor_asn_map() -> Dict[str, List[str]]:
    """返回 {vendor: [AS123, AS456, ...]}"""
    return {v: list(info.get("asn", [])) for v, info in CDN_DATA.items()}


# ======================================================================
# 源 1: Cloudflare 官方 (ips-v4 / ips-v6)
# ======================================================================
def fetch_cloudflare() -> Tuple[List[Tuple[str, str]], List[Tuple[str, str]], Dict]:
    """返回 (v4_cidrs, v6_cidrs, report)"""
    v4, v6 = [], []
    report = {"source": "Cloudflare 官方", "ok": False}
    headers = {"User-Agent": USER_AGENT}
    try:
        r1 = requests.get("https://www.cloudflare.com/ips-v4",
                          headers=headers, timeout=DEFAULT_TIMEOUT)
        if r1.ok:
            for line in r1.text.splitlines():
                cidr = line.strip()
                if _is_valid_cidr(cidr):
                    v4.append(("Cloudflare", cidr))
        r2 = requests.get("https://www.cloudflare.com/ips-v6",
                          headers=headers, timeout=DEFAULT_TIMEOUT)
        if r2.ok:
            for line in r2.text.splitlines():
                cidr = line.strip()
                if _is_valid_cidr(cidr):
                    v6.append(("Cloudflare", cidr))
        report.update(ok=True, v4=len(v4), v6=len(v6))
    except Exception as e:
        report["error"] = str(e)[:80]
    return v4, v6, report


# ======================================================================
# 源 2: AWS CloudFront 官方 JSON
# ======================================================================
def fetch_aws_cloudfront() -> Tuple[List[Tuple[str, str]], List[Tuple[str, str]], Dict]:
    v4, v6 = [], []
    report = {"source": "AWS CloudFront 官方", "ok": False}
    try:
        r = requests.get(
            "https://d7uri8nf7uskq.cloudfront.net/tools/list-cloudfront-ips",
            headers={"User-Agent": USER_AGENT}, timeout=DEFAULT_TIMEOUT,
        )
        if r.ok:
            data = r.json()
            for key in ("CLOUDFRONT_GLOBAL_IP_LIST", "CLOUDFRONT_REGIONAL_EDGE_IP_LIST"):
                for cidr in data.get(key, []):
                    if not _is_valid_cidr(cidr):
                        continue
                    net = ipaddress.ip_network(cidr, strict=False)
                    (v4 if net.version == 4 else v6).append(("Amazon CloudFront", cidr))
            report.update(ok=True, v4=len(v4), v6=len(v6))
    except Exception as e:
        report["error"] = str(e)[:80]
    return v4, v6, report


# ======================================================================
# 源 3: Fastly 官方 public-ip-list
# ======================================================================
def fetch_fastly() -> Tuple[List[Tuple[str, str]], List[Tuple[str, str]], Dict]:
    v4, v6 = [], []
    report = {"source": "Fastly 官方", "ok": False}
    try:
        r = requests.get("https://api.fastly.com/public-ip-list",
                         headers={"User-Agent": USER_AGENT}, timeout=DEFAULT_TIMEOUT)
        if r.ok:
            for line in r.text.splitlines():
                cidr = line.strip()
                if not _is_valid_cidr(cidr):
                    continue
                net = ipaddress.ip_network(cidr, strict=False)
                (v4 if net.version == 4 else v6).append(("Fastly", cidr))
            report.update(ok=True, v4=len(v4), v6=len(v6))
    except Exception as e:
        report["error"] = str(e)[:80]
    return v4, v6, report


# ======================================================================
# 源 4: Azure ServiceTags (FrontDoor / CDN)
# ======================================================================
AZURE_TAGS_URL = (
    "https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/"
    "ServiceTags_Public_20250101.json"
)


def fetch_azure() -> Tuple[List[Tuple[str, str]], List[Tuple[str, str]], Dict]:
    v4, v6 = [], []
    report = {"source": "Azure ServiceTags", "ok": False}
    try:
        r = requests.get(AZURE_TAGS_URL, headers={"User-Agent": USER_AGENT},
                         timeout=60)
        if r.ok:
            data = r.json()
            for tag in data.get("values", []):
                name = (tag.get("id") or "").lower()
                tag_name = tag.get("name", "")
                # 仅保留 FrontDoor / CDN 相关标签
                if not ("frontdoor" in name or tag_name.startswith("AzureFrontDoor")
                        or tag_name.startswith("AzureCdn")):
                    continue
                for cidr in tag.get("properties", {}).get("addressPrefixes", []):
                    if not _is_valid_cidr(cidr):
                        continue
                    net = ipaddress.ip_network(cidr, strict=False)
                    (v4 if net.version == 4 else v6).append(("Azure Front Door", cidr))
            report.update(ok=True, v4=len(v4), v6=len(v6))
    except Exception as e:
        report["error"] = str(e)[:80]
    return v4, v6, report


# ======================================================================
# 源 5: GCP Cloud IP Ranges (DNS TXT 解析)
# ======================================================================
def fetch_gcp() -> Tuple[List[Tuple[str, str]], List[Tuple[str, str]], Dict]:
    v4, v6 = [], []
    report = {"source": "GCP Cloud IP Ranges", "ok": False}
    try:
        # 直接拉 Google Cloud 官方 JSON (cloud-netblocks 聚合)
        r = requests.get("https://www.gstatic.com/ipranges/cloud",
                         headers={"User-Agent": USER_AGENT}, timeout=DEFAULT_TIMEOUT)
        if r.ok:
            data = r.json()
            for item in data.get("prefixes", []):
                cidr = item.get("ipv4Prefix") or item.get("ipv6Prefix")
                if not cidr or not _is_valid_cidr(cidr):
                    continue
                net = ipaddress.ip_network(cidr, strict=False)
                (v4 if net.version == 4 else v6).append(("Google Cloud CDN", cidr))
            report.update(ok=True, v4=len(v4), v6=len(v6))
    except Exception as e:
        report["error"] = str(e)[:80]
    return v4, v6, report


# ======================================================================
# 源 6: bgpview.io 按 ASN 拉取 (覆盖全部有 ASN 的厂商)
# ======================================================================
def fetch_bgpview(vendor_asn: Dict[str, List[str]]) -> Tuple[List[Tuple[str, str]], List[Tuple[str, str]], Dict]:
    v4, v6 = [], []
    report = {"source": "bgpview.io (ASN)", "ok": False, "asns": 0, "errors": 0}
    headers = {"User-Agent": USER_AGENT}

    def _one(vendor: str, asn: str) -> Tuple[List, List]:
        asn_num = str(asn).lstrip("ASasAS")
        url = f"https://api.bgpview.io/asn/{asn_num}/prefixes"
        lv4, lv6 = [], []
        try:
            r = requests.get(url, headers=headers, timeout=DEFAULT_TIMEOUT)
            if r.ok:
                data = r.json()
                for item in data.get("data", {}).get("ipv4_prefixes", []):
                    cidr = item.get("prefix")
                    if cidr and _is_valid_cidr(cidr):
                        lv4.append((vendor, str(ipaddress.ip_network(cidr, strict=False))))
                for item in data.get("data", {}).get("ipv6_prefixes", []):
                    cidr = item.get("prefix")
                    if cidr and _is_valid_cidr(cidr):
                        lv6.append((vendor, str(ipaddress.ip_network(cidr, strict=False))))
        except Exception:
            report["errors"] += 1
        return lv4, lv6

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futures = {ex.submit(_one, v, a): (v, a) for v, asns in vendor_asn.items() for a in asns}
        for fut in concurrent.futures.as_completed(futures):
            report["asns"] += 1
            try:
                lv4, lv6 = fut.result()
                v4.extend(lv4)
                v6.extend(lv6)
            except Exception:
                report["errors"] += 1
    report.update(ok=len(v4) + len(v6) > 0, v4=len(v4), v6=len(v6))
    return v4, v6, report


# ======================================================================
# 源 7: RIPE Stat API 按 ASN 拉取 (权威当前 BGP)
# ======================================================================
def fetch_ripestat(vendor_asn: Dict[str, List[str]]) -> Tuple[List[Tuple[str, str]], List[Tuple[str, str]], Dict]:
    v4, v6 = [], []
    report = {"source": "RIPE Stat (ASN)", "ok": False, "asns": 0, "errors": 0}
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}

    def _one(vendor: str, asn: str) -> Tuple[List, List]:
        asn_num = str(asn).lstrip("ASasAS")
        url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn_num}"
        lv4, lv6 = [], []
        try:
            r = requests.get(url, headers=headers, timeout=DEFAULT_TIMEOUT)
            if r.ok:
                data = r.json()
                for item in data.get("data", {}).get("prefixes", []):
                    cidr = item.get("prefix")
                    if cidr and _is_valid_cidr(cidr):
                        net = ipaddress.ip_network(cidr, strict=False)
                        (lv4 if net.version == 4 else lv6).append((vendor, str(net)))
        except Exception:
            report["errors"] += 1
        return lv4, lv6

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futures = {ex.submit(_one, v, a): (v, a) for v, asns in vendor_asn.items() for a in asns}
        for fut in concurrent.futures.as_completed(futures):
            report["asns"] += 1
            try:
                lv4, lv6 = fut.result()
                v4.extend(lv4)
                v6.extend(lv6)
            except Exception:
                report["errors"] += 1
    report.update(ok=len(v4) + len(v6) > 0, v4=len(v4), v6=len(v6))
    return v4, v6, report


# ======================================================================
# 源 8: RADB whois (权威路由注册, 可能不全)
# ======================================================================
def fetch_radb(vendor_asn: Dict[str, List[str]]) -> Tuple[List[Tuple[str, str]], List[Tuple[str, str]], Dict]:
    v4, v6 = [], []
    report = {"source": "RADB whois", "ok": False, "asns": 0, "errors": 0}

    def _whois_one(asn: str) -> List[Tuple[str, str]]:
        asn_num = str(asn).lstrip("ASasAS")
        routes: List[Tuple[str, str]] = []
        try:
            # whois -h whois.radb.net -- '-i origin AS<N>'
            proc = subprocess.run(
                ["whois", "-h", "whois.radb.net", f"-i origin AS{asn_num}"],
                capture_output=True, timeout=20, text=True,
            )
            for line in proc.stdout.splitlines():
                line = line.strip()
                if line.startswith("route:") or line.startswith("route6:"):
                    cidr = line.split(":", 1)[1].strip()
                    if _is_valid_cidr(cidr):
                        routes.append(("", str(ipaddress.ip_network(cidr, strict=False))))
        except FileNotFoundError:
            report["error"] = "whois 命令未安装, 跳过 RADB 源"
        except subprocess.TimeoutExpired:
            report["errors"] += 1
        except Exception:
            report["errors"] += 1
        return routes

    # 用厂商名回填 vendor (whois 不返回厂商)
    all_asns = [(v, a) for v, asns in vendor_asn.items() for a in asns]
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
        futures = {ex.submit(_whois_one, a): v for v, a in all_asns}
        for fut in concurrent.futures.as_completed(futures):
            v = futures[fut]
            report["asns"] += 1
            try:
                routes = fut.result()
                for _, cidr in routes:
                    net = ipaddress.ip_network(cidr, strict=False)
                    (v4 if net.version == 4 else v6).append((v, cidr))
            except Exception:
                report["errors"] += 1
    report.update(ok=len(v4) + len(v6) > 0, v4=len(v4), v6=len(v6))
    return v4, v6, report


# ======================================================================
# 8 源并发调度
# ======================================================================
SOURCES = {
    "cloudflare":  fetch_cloudflare,
    "aws":         fetch_aws_cloudfront,
    "fastly":      fetch_fastly,
    "azure":       fetch_azure,
    "gcp":         fetch_gcp,
    # bgpview/ripe/radb 需要 vendor_asn 参数, 单独处理
}


def collect_all(vendors: Optional[List[str]] = None,
                workers: int = 16) -> Dict:
    """8 源并发拉取, 返回完整结果 dict

    参数:
        vendors: 限定厂商列表 (None=全部)
        workers: 线程池大小

    返回: {
        "meta": {...},
        "vendors": {vendor: {"v4": [...], "v6": [...]}},
        "raw_sources": {source_name: report},
    }
    """
    t0 = time.time()
    vendor_asn_all = _vendor_asn_map()
    if vendors:
        # 过滤指定厂商 (按厂商名精确匹配)
        vendor_asn = {v: a for v, a in vendor_asn_all.items() if v in vendors}
    else:
        vendor_asn = vendor_asn_all

    print(f"[深度收集] 目标厂商: {len(vendor_asn)} 家 | ASN 数: "
          f"{sum(len(a) for a in vendor_asn.values())}")
    print(f"[深度收集] 启动 8 源并发拉取 (workers={workers})...")

    all_v4: List[Tuple[str, str]] = []
    all_v6: List[Tuple[str, str]] = []
    source_reports: Dict[str, Dict] = {}

    # 并发调度: 官方源 (5 个) + ASN 源 (3 个, 共享 vendor_asn)
    asn_jobs = {"bgpview": fetch_bgpview, "ripe": fetch_ripestat, "radb": fetch_radb}

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures: Dict = {}
        # 官方源
        for name, fn in SOURCES.items():
            futures[ex.submit(fn)] = name
        # ASN 源
        for name, fn in asn_jobs.items():
            futures[ex.submit(fn, vendor_asn)] = name

        for fut in concurrent.futures.as_completed(futures):
            name = futures[fut]
            try:
                v4, v6, rep = fut.result()
                all_v4.extend(v4)
                all_v6.extend(v6)
                source_reports[name] = rep
                status = "OK" if rep.get("ok") else "FAIL"
                print(f"  [{status}] {rep.get('source', name):30s} "
                      f"v4={rep.get('v4', 0):6d} v6={rep.get('v6', 0):6d}"
                      + (f" err={rep['error']}" if rep.get("error") else ""))
            except Exception as e:
                source_reports[name] = {"source": name, "ok": False, "error": str(e)[:80]}
                print(f"  [EXC ] {name:30s} 异常: {e}")

    # 按 vendor 聚合 + 去重
    vendor_map: Dict[str, Dict[str, Set[str]]] = {}
    for vendor, cidr in all_v4:
        vendor_map.setdefault(vendor, {"v4": set(), "v6": set()})["v4"].add(cidr)
    for vendor, cidr in all_v6:
        vendor_map.setdefault(vendor, {"v4": set(), "v6": set()})["v6"].add(cidr)

    # 合并静态库的厂商 (即使在线未拉到也保留空, 保证 cdn_ranges 兼容)
    for v in CDN_DATA:
        vendor_map.setdefault(v, {"v4": set(), "v6": set()})

    vendors_out = {
        v: {"v4": sorted(s["v4"]), "v6": sorted(s["v6"])}
        for v, s in vendor_map.items()
    }

    total_v4 = sum(len(s["v4"]) for s in vendors_out.values())
    total_v6 = sum(len(s["v6"]) for s in vendors_out.values())

    meta = {
        "fetched_at": datetime.now().isoformat(),
        "duration_sec": round(time.time() - t0, 2),
        "vendor_count": len(vendors_out),
        "totals": {"v4": total_v4, "v6": total_v6},
        "sources": {n: {k: v for k, v in r.items() if k != "error"}
                    for n, r in source_reports.items()},
        "description": "cdn_ip_collector 8 源深度收集, 与 cdn_ranges.py 兼容",
    }
    print(f"\n[深度收集] 完成: {meta['duration_sec']}s | "
          f"厂商 {len(vendors_out)} | v4 {total_v4} | v6 {total_v6}")

    return {"meta": meta, "vendors": vendors_out, "raw_sources": source_reports}


# ======================================================================
# 持久化
# ======================================================================
def save_json(result: Dict, path: str) -> None:
    """保存为 cdn_ranges.py 兼容的 JSON 格式"""
    payload = {
        "meta": result["meta"],
        "vendors": result["vendors"],
    }
    Path(path).write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                          encoding="utf-8")
    print(f"[+] 已保存: {path} (可被 cdn_ranges.py --load-full 加载)")


def load_json(path: str) -> Optional[Dict]:
    """加载已存在的 JSON"""
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return None


def merge_text(result: Dict) -> str:
    """合并为纯文本 CIDR 列表 (供管道 / 黑名单使用)"""
    lines = [f"# cdn_ip_collector 合并输出 | 生成于 {result['meta']['fetched_at']}"]
    for vendor, ranges in sorted(result["vendors"].items()):
        for cidr in ranges["v4"]:
            lines.append(f"{cidr} # {vendor} v4")
        for cidr in ranges["v6"]:
            lines.append(f"{cidr} # {vendor} v6")
    return "\n".join(lines)


# ======================================================================
# CLI
# ======================================================================
def _parse_vendors(arg: Optional[str]) -> Optional[List[str]]:
    """解析 --vendor "Cloudflare,阿里云 CDN" 为列表"""
    if not arg:
        return None
    return [v.strip() for v in arg.split(",") if v.strip()]


def _main() -> int:
    parser = argparse.ArgumentParser(
        description="cdn_ip_collector — CDN 厂商 IP 段 8 源深度收集器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python cdn_ip_collector.py                            # 全量 8 源拉取
  python cdn_ip_collector.py --vendor Cloudflare,"阿里云 CDN"
  python cdn_ip_collector.py --output cdn_ranges_full.json
  python cdn_ip_collector.py --workers 16
  python cdn_ip_collector.py --merge > all_cdn_ranges.txt
  python cdn_ip_collector.py --load                     # 仅加载已有结果

输出 JSON 可直接被 cdn_ranges.py 加载:
  python cdn_ranges.py --load-full cdn_ranges_full.json
        """,
    )
    parser.add_argument("--vendor", "-v", help='限定厂商, 逗号分隔, 如 "Cloudflare,阿里云 CDN"')
    parser.add_argument("--output", "-o", default=DEFAULT_OUTPUT,
                        help=f"输出 JSON 文件 (默认 {DEFAULT_OUTPUT})")
    parser.add_argument("--workers", "-w", type=int, default=16, help="并发线程数 (默认 16)")
    parser.add_argument("--merge", action="store_true",
                        help="输出合并文本 CIDR 列表到 stdout (适合管道/黑名单)")
    parser.add_argument("--load", action="store_true",
                        help="仅加载已有 JSON, 不重新拉取 (配合 --output)")
    parser.add_argument("--no-save", action="store_true",
                        help="不保存 JSON (仅与 --merge 配合)")
    args = parser.parse_args()

    vendors = _parse_vendors(args.vendor)

    # --load 模式: 直接读已有 JSON
    if args.load:
        result = load_json(args.output)
        if not result:
            print(f"[错误] 无法加载 {args.output}, 请先执行一次完整拉取", file=sys.stderr)
            return 2
        print(f"[加载] {args.output} | 厂商 {len(result.get('vendors', {}))} | "
              f"v4 {result['meta']['totals']['v4']} | v6 {result['meta']['totals']['v6']}")
    else:
        # 校验厂商名
        if vendors:
            unknown = [v for v in vendors if v not in CDN_DATA]
            if unknown:
                print(f"[警告] 未识别的厂商名: {unknown}")
                print(f"       可用厂商: {', '.join(list(CDN_DATA.keys())[:10])} ...")
        result = collect_all(vendors=vendors, workers=args.workers)
        if not args.no_save and not args.merge:
            save_json(result, args.output)

    # --merge 模式: 输出文本
    if args.merge:
        print(merge_text(result))
        return 0

    # 默认: 终端摘要
    print("\n" + "=" * 70)
    print("  深度收集结果摘要")
    print("=" * 70)
    print(f"  生成时间:   {result['meta']['fetched_at']}")
    print(f"  耗时:       {result['meta'].get('duration_sec', '-')}s")
    print(f"  厂商数:     {result['meta']['vendor_count']}")
    print(f"  IPv4 段:    {result['meta']['totals']['v4']}")
    print(f"  IPv6 段:    {result['meta']['totals']['v6']}")
    print("\n  各源状态:")
    for name, rep in result.get("raw_sources", result["meta"].get("sources", {})).items():
        status = "OK" if rep.get("ok") else "FAIL"
        print(f"    [{status}] {rep.get('source', name):30s} "
              f"v4={rep.get('v4', 0):6d} v6={rep.get('v6', 0):6d}")
    print("\n  Top 10 厂商 (按 v4 段数):")
    sorted_v = sorted(result["vendors"].items(),
                      key=lambda x: len(x[1]["v4"]), reverse=True)[:10]
    for v, r in sorted_v:
        print(f"    {v:30s} v4={len(r['v4']):5d}  v6={len(r['v6']):5d}")

    if not args.load and not args.no_save:
        print(f"\n  JSON 已保存: {args.output}")
        print(f"  联动命令:    python cdn_ranges.py --load-full {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
