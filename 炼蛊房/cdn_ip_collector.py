#!/usr/bin/env python3
"""cdn_ip_collector.py — 深度 CDN IP 段收集器（8 源并发）
从 Cloudflare/AWS/Azure/Fastly/GCP 官方源 + bgpview + RIPE Stat + RADB
按 ASN 并发拉取全部前缀，合并去重后输出。

用法:
  python3 cdn_ip_collector.py                          # 全量拉取
  python3 cdn_ip_collector.py --vendor Cloudflare      # 仅指定厂商
  python3 cdn_ip_collector.py --merge > all_ranges.txt # 输出纯 CIDR
  python3 cdn_ip_collector.py --output my.json         # 指定输出
  python3 cdn_ip_collector.py --workers 16             # 并发数

来源: cdn-origin-tracing SKILL v5.1
"""
import argparse, json, ipaddress, sys, re
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
except ImportError:
    print("需要 requests: pip install requests", file=sys.stderr)
    sys.exit(1)

TIMEOUT = 15

# ASN → 厂商映射（43 个 ASN，部分厂商共享 ASN）
ASN_MAP: dict[str, list[str]] = {
    "13335": ["Cloudflare"],
    "16509": ["Amazon CloudFront"],
    "20940": ["Akamai"], "16625": ["Akamai"],
    "54113": ["Fastly"],
    "15169": ["Google Cloud CDN"],
    "8075":  ["Azure Front Door"],
    "19551": ["Imperva Incapsula"],
    "54825": ["Sucuri"], "399758": ["Sucuri"],
    "33438": ["StackPath"], "64600": ["StackPath"],
    "15133": ["Edgecast"],
    "60068": ["CDN77"],
    "200919": ["BunnyCDN"],
    "61317": ["KeyCDN"],
    "199524": ["Gcore"],
    "20428": ["Quantil"],
    "60626": ["Leaseweb CDN"],
    "43350": ["HiberniaCDN"],
    "36414": ["CDNetworks"],
    "208827": ["ArvanCloud"],
    "37963": ["阿里云 CDN"],
    "45090": ["腾讯云 CDN"], "133478": ["腾讯云 CDN"],
    "38365": ["百度云加速"],
    "48024": ["又拍云"],
    "9801":  ["七牛云", "网宿", "360 CDN"],
    "4811":  ["网宿 ChinaNetCenter"],
    "4808":  ["帝联 Dnion"],
    "136990": ["华为云 CDN"], "55566": ["华为云 CDN"],
    "137673": ["火山引擎 CDN"],
    "59019": ["金山云"],
    "63758": ["UCloud CDN"],
    "59026": ["京东云 CDN"],
    "133823": ["白山云"],
    "45102": ["网易云"],
    "23724": ["天翼云"],
    "59344": ["青云 CDN"],
    "56040": ["西部数码"],
}

# ── 官方源 ──
OFFICIAL_SOURCES: dict[str, dict] = {
    "Cloudflare": {
        "urls": [
            "https://www.cloudflare.com/ips-v4",
            "https://www.cloudflare.com/ips-v6",
        ],
        "parser": "text_lines",
    },
    "Amazon CloudFront": {
        "urls": [
            "https://d7uri8nf7uskq.cloudfront.net/tools/list-cloudfront-ips",
        ],
        "parser": "aws_json",
    },
    "Fastly": {
        "urls": ["https://api.fastly.com/public-ip-list"],
        "parser": "fastly_json",
    },
}

CIDR_RE = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})')
CIDR6_RE = re.compile(r'([0-9a-fA-F:]+/\d{1,3})')


def _parse_text_lines(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines()
            if line.strip() and ('/' in line)]


def _parse_aws_json(text: str) -> list[str]:
    data = json.loads(text)
    cidrs = data.get("CLOUDFRONT_GLOBAL_IP_LIST", [])
    cidrs += data.get("CLOUDFRONT_REGIONAL_EDGE_IP_LIST", [])
    return cidrs


def _parse_fastly_json(text: str) -> list[str]:
    data = json.loads(text)
    return data.get("addresses", []) + data.get("ipv6_addresses", [])


def fetch_official(vendor: str) -> list[str]:
    src = OFFICIAL_SOURCES.get(vendor)
    if not src:
        return []
    cidrs = []
    for url in src["urls"]:
        try:
            r = requests.get(url, timeout=TIMEOUT, verify=False)
            r.raise_for_status()
            parser = src["parser"]
            if parser == "text_lines":
                cidrs += _parse_text_lines(r.text)
            elif parser == "aws_json":
                cidrs += _parse_aws_json(r.text)
            elif parser == "fastly_json":
                cidrs += _parse_fastly_json(r.text)
        except Exception as e:
            print(f"  官方源 {vendor} {url}: {e}", file=sys.stderr)
    return cidrs


def fetch_bgpview(asn: str) -> list[str]:
    try:
        r = requests.get(f"https://api.bgpview.io/asn/{asn}/prefixes",
                         timeout=TIMEOUT, verify=False)
        data = r.json().get("data", {})
        v4 = [p["prefix"] for p in data.get("ipv4_prefixes", [])]
        v6 = [p["prefix"] for p in data.get("ipv6_prefixes", [])]
        return v4 + v6
    except Exception:
        return []


def fetch_ripestat(asn: str) -> list[str]:
    try:
        r = requests.get(
            f"https://stat.ripe.net/data/announced-prefixes/data.json"
            f"?resource=AS{asn}",
            timeout=TIMEOUT, verify=False)
        data = r.json().get("data", {}).get("prefixes", [])
        return [p["prefix"] for p in data]
    except Exception:
        return []


def collect_asn(asn: str) -> dict:
    """对单个 ASN 从 3 个源并发拉取"""
    vendors = ASN_MAP.get(asn, [f"AS{asn}"])
    cidrs = set()
    with ThreadPoolExecutor(max_workers=3) as ex:
        futures = {
            ex.submit(fetch_bgpview, asn): "bgpview",
            ex.submit(fetch_ripestat, asn): "ripestat",
        }
        if vendors[0] in OFFICIAL_SOURCES:
            futures[ex.submit(fetch_official, vendors[0])] = "official"
        for f in as_completed(futures):
            try:
                cidrs.update(f.result())
            except Exception:
                pass
    return {"vendors": vendors, "cidrs": sorted(cidrs)}


def merge_adjacent(cidrs: list[str]) -> list[str]:
    """合并相邻 CIDR（1.0.0.0/24 + 1.0.1.0/24 → 1.0.0.0/23）"""
    nets = []
    for c in cidrs:
        try:
            nets.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            pass
    v4 = sorted(n for n in nets if isinstance(n, ipaddress.IPv4Network))
    v6 = sorted(n for n in nets if isinstance(n, ipaddress.IPv6Network))
    merged = list(ipaddress.collapse_addresses(v4))
    merged += list(ipaddress.collapse_addresses(v6))
    return [str(n) for n in merged]


def main():
    ap = argparse.ArgumentParser(description="CDN IP 段深度收集器")
    ap.add_argument("--vendor", nargs="+", help="仅拉取指定厂商")
    ap.add_argument("--output", default="cdn_ranges_full.json")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--merge", action="store_true",
                    help="输出合并后的纯 CIDR 列表到 stdout")
    args = ap.parse_args()

    target_asns = set()
    if args.vendor:
        vendor_set = set(v.strip() for v in args.vendor)
        for asn, vendors in ASN_MAP.items():
            if any(v in vendor_set for v in vendors):
                target_asns.add(asn)
    else:
        target_asns = set(ASN_MAP.keys())

    print(f"[*] 收集 {len(target_asns)} 个 ASN ...", file=sys.stderr)
    all_result: dict[str, list[str]] = {}
    total = 0

    seen_asn = set()
    asn_list = []
    for asn in target_asns:
        if asn not in seen_asn:
            seen_asn.add(asn)
            asn_list.append(asn)

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {ex.submit(collect_asn, asn): asn for asn in asn_list}
        for f in as_completed(futures):
            asn = futures[f]
            try:
                result = f.result()
                vendors = result["vendors"]
                cidrs = result["cidrs"]
                merged = merge_adjacent(cidrs)
                for v in vendors:
                    existing = all_result.get(v, [])
                    all_result[v] = merge_adjacent(existing + merged)
                count = len(merged)
                total += count
                print(f"  AS{asn} ({', '.join(vendors)}): {count} 段",
                      file=sys.stderr)
            except Exception as e:
                print(f"  AS{asn}: 失败 {e}", file=sys.stderr)

    if args.merge:
        all_cidrs = []
        for cidrs in all_result.values():
            all_cidrs.extend(cidrs)
        for c in merge_adjacent(all_cidrs):
            print(c)
    else:
        out_path = Path(args.output)
        if not out_path.is_absolute():
            out_path = Path(__file__).parent / out_path
        out_path.write_text(json.dumps(all_result, indent=2, ensure_ascii=False))
        print(f"[+] 保存到 {out_path} ({total} 段, "
              f"{len(all_result)} 厂商)", file=sys.stderr)


if __name__ == "__main__":
    main()
