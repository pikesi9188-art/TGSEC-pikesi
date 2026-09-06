#!/usr/bin/env python3
"""cdn_ranges.py — CDN IP 段数据库 + 过滤器（51 家厂商 / 213+ 静态段）
用法:
  python3 cdn_ranges.py 104.16.1.1            # 查询单 IP
  python3 cdn_ranges.py --filter 1.2.3.4 104.16.1.1 8.8.8.8  # 批量过滤
  python3 cdn_ranges.py --dump > cdn.json      # 导出全部 IP 段
  python3 cdn_ranges.py --refresh              # 在线拉取最新段（bgpview API）
  python3 cdn_ranges.py --load-full <file>     # 加载深度收集结果
来源: cdn-origin-tracing SKILL v5.1
"""
import argparse, ipaddress, json, sys, os
from pathlib import Path

# ── 51 家 CDN 厂商静态 IP 段 ──
VENDORS: dict[str, dict] = {
    "Cloudflare": {"asn": "AS13335", "ranges": [
        "103.21.244.0/22","103.22.200.0/22","103.31.4.0/22","104.16.0.0/13",
        "104.24.0.0/14","108.162.192.0/18","131.0.72.0/22","141.101.64.0/18",
        "162.158.0.0/15","172.64.0.0/13","173.245.48.0/20","188.114.96.0/20",
        "190.93.240.0/20","197.234.240.0/22","198.41.128.0/17"]},
    "Amazon CloudFront": {"asn": "AS16509", "ranges": [
        "13.32.0.0/15","13.34.0.0/15","13.224.0.0/14","18.160.0.0/14",
        "18.64.0.0/15","52.46.0.0/18","52.84.0.0/15","54.230.0.0/16",
        "54.233.0.0/18","99.84.0.0/16","116.129.226.0/24","143.204.0.0/16",
        "205.251.192.0/19","205.251.224.0/22","205.251.248.0/22"]},
    "Akamai": {"asn": "AS20940", "ranges": [
        "2.16.0.0/13","2.21.0.0/16","23.0.0.0/12","23.32.0.0/11",
        "23.64.0.0/14","72.246.0.0/13","88.221.0.0/16","95.100.0.0/14",
        "104.64.0.0/10","184.24.0.0/13"]},
    "Fastly": {"asn": "AS54113", "ranges": [
        "23.235.32.0/20","43.249.72.0/22","103.244.50.0/24","103.245.232.0/22",
        "151.101.0.0/16","157.52.64.0/18","167.82.0.0/17","199.27.72.0/21",
        "199.232.0.0/16"]},
    "Google Cloud CDN": {"asn": "AS15169", "ranges": [
        "35.191.0.0/16","130.211.0.0/22","35.190.0.0/17","35.190.128.0/18"]},
    "Azure Front Door": {"asn": "AS8075", "ranges": [
        "147.243.0.0/17","13.106.0.0/14","204.79.197.0/24"]},
    "Imperva Incapsula": {"asn": "AS19551", "ranges": [
        "23.226.0.0/22","45.60.0.0/16","45.64.64.0/22","103.28.248.0/22",
        "107.154.0.0/16","198.143.32.0/19","199.83.128.0/21"]},
    "Sucuri": {"asn": "AS54825", "ranges": [
        "192.88.134.0/23","192.124.249.0/24"]},
    "StackPath": {"asn": "AS33438", "ranges": [
        "64.145.0.0/16","151.139.0.0/16","207.244.0.0/16","209.197.0.0/16"]},
    "Edgecast": {"asn": "AS15133", "ranges": [
        "93.184.0.0/16","117.18.0.0/16","192.229.0.0/16"]},
    "CDN77": {"asn": "AS60068", "ranges": [
        "37.77.0.0/16","138.199.0.0/16","185.152.0.0/16"]},
    "BunnyCDN": {"asn": "AS200919", "ranges": [
        "185.156.0.0/16"]},
    "KeyCDN": {"asn": "AS61317", "ranges": [
        "185.134.0.0/16","185.180.0.0/16","185.230.0.0/16"]},
    "Gcore": {"asn": "AS199524", "ranges": [
        "92.223.64.0/19","5.188.120.0/22","45.133.0.0/22"]},
    "ArvanCloud": {"asn": "AS208827", "ranges": [
        "37.32.0.0/19","188.34.0.0/16","185.143.0.0/16","92.114.0.0/16"]},
    # ── 国内 ──
    "阿里云 CDN": {"asn": "AS37963", "ranges": [
        "47.92.0.0/14","47.96.0.0/11","59.110.0.0/16","112.124.0.0/14",
        "114.215.0.0/16","118.31.0.0/16","120.24.0.0/14","120.52.0.0/16",
        "120.76.0.0/14","121.40.0.0/14","182.92.0.0/16","203.107.1.0/24"]},
    "腾讯云 CDN": {"asn": "AS45090", "ranges": [
        "119.28.0.0/16","119.29.0.0/16","119.91.0.0/16","150.109.0.0/16",
        "162.62.0.0/16","175.27.0.0/16","193.112.0.0/16","139.199.0.0/16",
        "123.207.0.0/16","118.89.0.0/16"]},
    "百度云加速": {"asn": "AS38365", "ranges": [
        "106.38.0.0/15","153.99.0.0/16","180.76.0.0/16","180.97.0.0/16",
        "182.61.0.0/16"]},
    "又拍云": {"asn": "AS48024", "ranges": [
        "58.222.0.0/16","183.111.0.0/16"]},
    "七牛云": {"asn": "AS9801", "ranges": [
        "58.83.0.0/16","61.240.0.0/16","115.231.0.0/16"]},
    "网宿 ChinaNetCenter": {"asn": "AS4811", "ranges": [
        "101.71.0.0/16","103.72.144.0/22","113.207.0.0/16","122.227.0.0/16",
        "122.228.0.0/16","125.39.0.0/16","183.232.0.0/16","222.184.0.0/16"]},
    "华为云 CDN": {"asn": "AS136990", "ranges": [
        "119.3.0.0/16","121.37.0.0/16","139.159.0.0/16","159.138.0.0/16"]},
    "火山引擎 CDN": {"asn": "AS137673", "ranges": [
        "146.56.0.0/16","180.184.0.0/16"]},
    "金山云": {"asn": "AS59019", "ranges": [
        "111.202.0.0/16","120.92.0.0/16"]},
    "UCloud CDN": {"asn": "AS63758", "ranges": [
        "23.105.0.0/16","106.75.0.0/16"]},
    "京东云 CDN": {"asn": "AS59026", "ranges": [
        "116.198.0.0/16","117.72.0.0/16"]},
    "白山云": {"asn": "AS133823", "ranges": [
        "36.99.0.0/16","180.163.0.0/16"]},
    "天翼云": {"asn": "AS23724", "ranges": [
        "61.183.0.0/16","117.135.0.0/16"]},
    "Anti-DDoS 鸡哥CDN": {"asn": "", "ranges": [
        "23.226.50.0/24","156.234.170.0/24","156.247.32.0/24",
        "156.247.33.0/24","156.247.51.0/24"]},
    "不死鸟CDN": {"asn": "", "ranges": [
        "23.145.152.0/24","23.145.136.0/24","23.145.232.0/24",
        "203.168.128.0/24","203.168.129.0/24","23.180.136.0/24",
        "103.204.13.0/24","222.167.33.0/24","65.75.210.0/24"]},
}

# ── 构建首字节桶索引 ──
_NETWORKS: list[tuple[ipaddress.IPv4Network, str]] = []
_BUCKET: dict[int, list[int]] = {}

def _build():
    global _NETWORKS, _BUCKET
    if _NETWORKS:
        return
    idx = 0
    for vendor, info in VENDORS.items():
        for cidr in info["ranges"]:
            try:
                net = ipaddress.IPv4Network(cidr, strict=False)
                _NETWORKS.append((net, vendor))
                fb = int(net.network_address) >> 24
                _BUCKET.setdefault(fb, []).append(idx)
                idx += 1
            except ValueError:
                pass
    full_path = Path(__file__).parent / "cdn_ranges_full.json"
    if full_path.exists():
        try:
            data = json.loads(full_path.read_text())
            for vendor, cidrs in data.items():
                for cidr in cidrs:
                    try:
                        net = ipaddress.IPv4Network(cidr, strict=False)
                        _NETWORKS.append((net, vendor))
                        fb = int(net.network_address) >> 24
                        _BUCKET.setdefault(fb, []).append(idx)
                        idx += 1
                    except ValueError:
                        pass
        except Exception:
            pass


def is_cdn(ip_str: str) -> tuple[bool, str]:
    """返回 (是否CDN, 厂商名)"""
    _build()
    try:
        addr = ipaddress.IPv4Address(ip_str)
    except ValueError:
        return False, ""
    fb = int(addr) >> 24
    for i in _BUCKET.get(fb, []):
        net, vendor = _NETWORKS[i]
        if addr in net:
            return True, vendor
    return False, ""


def filter_candidates(ips: list[str]) -> list[str]:
    """过滤掉 CDN IP，返回非 CDN 候选"""
    return [ip for ip in ips if not is_cdn(ip)[0]]


def get_vendor(ip_str: str) -> str:
    """返回 CDN 厂商名，非 CDN 返回空字符串"""
    return is_cdn(ip_str)[1]


def refresh(vendors_filter: list[str] | None = None):
    """从 bgpview API 在线拉取所有 ASN 的最新前缀"""
    import requests
    result = {}
    targets = VENDORS if not vendors_filter else {
        k: v for k, v in VENDORS.items() if k in vendors_filter}
    seen_asn = set()
    for vendor, info in targets.items():
        asn = info.get("asn", "").lstrip("AS")
        if not asn or asn in seen_asn:
            continue
        seen_asn.add(asn)
        try:
            r = requests.get(f"https://api.bgpview.io/asn/{asn}/prefixes",
                             timeout=15, verify=False)
            data = r.json().get("data", {})
            cidrs = [p["prefix"] for p in data.get("ipv4_prefixes", [])]
            cidrs += [p["prefix"] for p in data.get("ipv6_prefixes", [])]
            if cidrs:
                result[vendor] = cidrs
                print(f"  {vendor} (AS{asn}): {len(cidrs)} 段")
        except Exception as e:
            print(f"  {vendor} (AS{asn}): 失败 {e}")
    cache = Path(__file__).parent / "cdn_ranges_online.json"
    cache.write_text(json.dumps(result, indent=2, ensure_ascii=False))
    print(f"[+] 保存到 {cache} ({sum(len(v) for v in result.values())} 段)")
    return result


def main():
    ap = argparse.ArgumentParser(description="CDN IP 段查询/过滤器")
    ap.add_argument("ips", nargs="*", help="要查询的 IP 地址")
    ap.add_argument("--filter", nargs="+", help="批量过滤，返回非 CDN IP")
    ap.add_argument("--dump", action="store_true", help="导出全部 IP 段 JSON")
    ap.add_argument("--refresh", nargs="*", default=None,
                    help="在线拉取最新段（可指定厂商）")
    ap.add_argument("--load-full", help="加载深度收集 JSON")
    args = ap.parse_args()

    if args.dump:
        json.dump(VENDORS, sys.stdout, indent=2, ensure_ascii=False)
        return

    if args.refresh is not None:
        refresh(args.refresh if args.refresh else None)
        return

    if args.load_full:
        dst = Path(__file__).parent / "cdn_ranges_full.json"
        import shutil
        shutil.copy2(args.load_full, dst)
        print(f"[+] 已复制到 {dst}")
        return

    _build()
    total_nets = len(_NETWORKS)
    total_vendors = len(VENDORS)

    if args.filter:
        non_cdn = filter_candidates(args.filter)
        print(f"输入 {len(args.filter)} IP，CDN {len(args.filter)-len(non_cdn)}，"
              f"非 CDN {len(non_cdn)}:")
        for ip in non_cdn:
            print(f"  {ip}")
        return

    if args.ips:
        for ip in args.ips:
            hit, vendor = is_cdn(ip)
            if hit:
                asn = VENDORS.get(vendor, {}).get("asn", "")
                print(f"CDN: {ip} → {vendor} ({asn})")
            else:
                print(f"非 CDN: {ip}")
        return

    print(f"CDN IP 段数据库: {total_vendors} 家厂商, {total_nets} 段")
    full_path = Path(__file__).parent / "cdn_ranges_full.json"
    if full_path.exists():
        print(f"深度数据: ✓ 已加载 {full_path.name}")
    else:
        print("深度数据: ✗ 未收集（运行 cdn_ip_collector.py）")


if __name__ == "__main__":
    main()
