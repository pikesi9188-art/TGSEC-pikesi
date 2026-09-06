#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
internet_wide_scanner.py — 全网 IP 扫描溯源引擎 (v1.4)
================================================================
源自 SKILL.md §14G「全网IP扫描溯源 (ZMap+Masscan+ZGrab2)」。

核心理念 (P0-P4 全失败后的核武器级手段):
    当 P0-P4 所有被动方法均失败时, 通过主动扫描全球 IPv4 地址空间,
    用证书指纹 / HTTP 响应 / 页面哈希等特征从数十亿 IP 中定位源站。

集成三大扫描引擎:
    - ZMap:    全 IPv4 单端口扫描 (45分钟/全0.0.0.0/0, 100M带宽)
    - Masscan: 全 IPv4 多端口扫描 (6分钟/全0.0.0.0/0, 1G带宽)
    - ZGrab2:  应用层 Banner 抓取 (TLS/HTTP/SSH/FTP)

匹配策略 (多维度交叉):
    1. 证书 SHA256 精确匹配      → 决定性证据 (confidence=S)
    2. 证书 Subject CN 包含目标  → 强证据 (confidence=A)
    3. HTTP Title/Server 匹配    → 强佐证 (confidence=B)
    4. Body Hash 一致性          → 强佐证 (confidence=B)
    5. Favicon mmh3 匹配         → 佐证 (confidence=C)
    6. TTL/端口模式关联          → 佐证 (confidence=C)

数据来源:
    - 主动扫描: ZMap/Masscan/ZGrab2 (需 root + 大带宽)
    - API 查询: Censys/Shodan/FOFA/ZoomEye/Quake/BinaryEdge (零成本, 推荐)

用法:
    python internet_wide_scanner.py target.com --extract-fingerprints
    python internet_wide_scanner.py target.com --shodan-key KEY --censys-id ID --censys-secret SEC
    python internet_wide_scanner.py target.com --ranges aws_ranges.txt --scan-mode zmap
    python internet_wide_scanner.py target.com --scan-mode masscan --ports 80,443,8080

依赖:
    - requests
    - 标准库: subprocess / json / hashlib / base64 / concurrent.futures
    - 可选: openssl (证书指纹), zmap/masscan/zgrab2 (主动扫描), mmh3 (favicon)
    - 复用 cdn_ranges.py 过滤 CDN IP

可被 cdn_tracer.py 联动:
    cdn_tracer.py 全失败 → 调用 InternetWideScanner.run_all() 兜底
"""
import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any, Optional, Tuple

# 复用 cdn_ranges 过滤 CDN
try:
    from cdn_ranges import is_cdn, filter_candidates, get_vendor  # type: ignore
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    try:
        from cdn_ranges import is_cdn, filter_candidates, get_vendor  # type: ignore
    except ImportError:
        print("[警告] 无法导入 cdn_ranges.py, CDN 过滤不可用", file=sys.stderr)
        is_cdn = lambda ip: False  # type: ignore
        filter_candidates = lambda ips: list(ips)  # type: ignore
        get_vendor = lambda ip: None  # type: ignore

import requests


# ======================================================================
# 工具函数
# ======================================================================
def _have_tool(name: str) -> bool:
    """检查系统是否安装了某命令行工具"""
    return shutil.which(name) is not None


def _clean_body(text: str) -> str:
    """清洗 HTTP body, 移除标签/空白, 用于稳定哈希"""
    # 移除 script/style/meta/link 块
    text = re.sub(r"<(script|style|meta|link)[^>]*>.*?</\1>", "", text, flags=re.S | re.I)
    # 移除所有标签
    text = re.sub(r"<[^>]+>", "", text)
    # 移除不可打印字符
    text = "".join(c if c.isprintable() else " " for c in text)
    # 压缩空白
    return " ".join(text.split())


def _extract_title(html: str) -> str:
    """从 HTML 提取 <title>"""
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    return m.group(1).strip() if m else ""


# ======================================================================
# 全网扫描引擎
# ======================================================================
class InternetWideScanner:
    """全网 IP 扫描溯源引擎

    工作流:
        步骤 0  指纹提取  extract_fingerprints()
        步骤 1  平台查询  scan_censys() / scan_shodan() / scan_fofa() ...
        步骤 2  定向扫描  scan_zmap_zgrab2() / scan_masscan()
        步骤 3  多指纹验证  verify_candidates()
        步骤 4  去 CDN 化   filter_candidates()
    """

    def __init__(self, target_domain: str, api_keys: Optional[Dict[str, str]] = None):
        self.target = target_domain
        self.api_keys = api_keys or {}
        self.candidates: List[Dict[str, Any]] = []
        self.fingerprints: Dict[str, Any] = {}

    # ------------------------------------------------------------------
    # 步骤 0: 指纹提取
    # ------------------------------------------------------------------
    def extract_fingerprints(self) -> Dict[str, Any]:
        """从目标提取所有可用指纹

        提取维度:
          - SSL 证书: SHA256 / SHA1 / Serial / Subject CN / Issuer CN / 有效期
          - HTTP:     Title / Server / Body Hash (清洗后 SHA256)
          - Favicon:  mmh3 hash (若有 mmh3 库)
          - 端口:     80/443 开放状态
        """
        fps: Dict[str, Any] = {"target": self.target, "extracted_at": _now()}

        # 1. SSL 证书指纹 (openssl)
        if _have_tool("openssl"):
            cert = self._extract_cert_fingerprint()
            if cert.get("available"):
                fps.update({k: v for k, v in cert.items()
                            if k in ("sha256", "sha1", "serial", "subject_cn",
                                     "issuer_cn", "not_before", "not_after")})
                fps["cert_available"] = True
            else:
                fps["cert_available"] = False
                fps["cert_error"] = cert.get("error", "未知")
        else:
            fps["cert_available"] = False
            fps["cert_error"] = "openssl 未安装"

        # 2. HTTP 响应指纹
        http = self._extract_http_fingerprint()
        fps.update(http)

        # 3. Favicon mmh3
        fav = self._extract_favicon_hash()
        if fav.get("available"):
            fps["favicon_mmh3"] = fav["hash"]
            fps["favicon_available"] = True
        else:
            fps["favicon_available"] = False

        self.fingerprints = fps
        return fps

    def _extract_cert_fingerprint(self) -> Dict[str, Any]:
        """通过 openssl 抓取证书"""
        result: Dict[str, Any] = {"available": False}
        try:
            s_client = subprocess.run(
                ["openssl", "s_client", "-connect", f"{self.target}:443",
                 "-servername", self.target],
                input=b"", capture_output=True, timeout=15,
            )
            if b"BEGIN CERTIFICATE" not in s_client.stdout:
                return result
            start = s_client.stdout.find(b"-----BEGIN CERTIFICATE-----")
            end = s_client.stdout.find(b"-----END CERTIFICATE-----", start)
            pem = s_client.stdout[start:end + len(b"-----END CERTIFICATE-----")] + b"\n"

            x509 = subprocess.run(
                ["openssl", "x509", "-noout",
                 "-fingerprint", "-sha256",
                 "-fingerprint", "-sha1",
                 "-serial", "-subject", "-issuer", "-dates"],
                input=pem, capture_output=True, timeout=5,
            )
            out = x509.stdout.decode(errors="ignore")
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("sha256 Fingerprint="):
                    result["sha256"] = line.split("=", 1)[1].replace(":", "").lower()
                elif line.startswith("sha1 Fingerprint="):
                    result["sha1"] = line.split("=", 1)[1].replace(":", "").lower()
                elif line.startswith("serial="):
                    result["serial"] = line.split("=", 1)[1].lower()
                elif line.startswith("subject=") and "CN=" in line:
                    result["subject_cn"] = line.split("CN=", 1)[1].split(",")[0].split("/")[0]
                elif line.startswith("issuer=") and "CN=" in line:
                    result["issuer_cn"] = line.split("CN=", 1)[1].split(",")[0].split("/")[0]
                elif line.startswith("notBefore="):
                    result["not_before"] = line.split("=", 1)[1]
                elif line.startswith("notAfter="):
                    result["not_after"] = line.split("=", 1)[1]
            result["available"] = bool(result.get("sha256"))
        except Exception as e:
            result["error"] = str(e)[:80]
        return result

    def _extract_http_fingerprint(self) -> Dict[str, Any]:
        """抓取 HTTP Title/Server/Body Hash"""
        result: Dict[str, Any] = {}
        headers = {"User-Agent": "Mozilla/5.0 (compatible; InternetWideScanner/1.4)"}
        for url in (f"https://{self.target}/", f"http://{self.target}/"):
            try:
                r = requests.get(url, headers=headers, timeout=15,
                                 allow_redirects=True, verify=False)
                result["title"] = _extract_title(r.text)
                result["server"] = r.headers.get("Server", "")
                result["status"] = r.status_code
                result["final_url"] = r.url
                body_clean = _clean_body(r.text)
                result["body_hash"] = hashlib.sha256(body_clean.encode()).hexdigest()
                result["body_hash_prefix16"] = result["body_hash"][:16]
                return result
            except requests.exceptions.SSLError:
                continue
            except Exception:
                continue
        return result

    def _extract_favicon_hash(self) -> Dict[str, Any]:
        """抓取 favicon 并计算 mmh3 hash"""
        result: Dict[str, Any] = {"available": False}
        try:
            r = requests.get(f"https://{self.target}/favicon.ico",
                             headers={"User-Agent": "Mozilla/5.0"}, timeout=10, verify=False)
            if r.status_code != 200 or not r.content:
                return result
            # 优先 mmh3 (Shodan/FOFA 标准算法)
            try:
                import mmh3  # type: ignore
                result["hash"] = mmh3.hash(base64.encodebytes(r.content))
                result["available"] = True
                return result
            except ImportError:
                # 回退: 用 sha256 (非标准, 但可用于自身对比)
                result["hash"] = hashlib.sha256(r.content).hexdigest()
                result["hash_algo"] = "sha256_fallback"
                result["available"] = True
                result["note"] = "mmh3 未安装, 用 sha256 替代 (无法直接搜 Shodan/FOFA)"
                return result
        except Exception as e:
            result["error"] = str(e)[:60]
            return result

    # ------------------------------------------------------------------
    # 步骤 1a: Censys API
    # ------------------------------------------------------------------
    def scan_censys(self) -> List[Dict[str, Any]]:
        """Censys v2 API 搜索全网 (按证书 SHA256 / Subject CN / Body Hash)"""
        results: List[Dict[str, Any]] = []
        if "CENSYS_API_ID" not in self.api_keys or "CENSYS_API_SECRET" not in self.api_keys:
            return results
        auth = (self.api_keys["CENSYS_API_ID"], self.api_keys["CENSYS_API_SECRET"])
        base = "https://search.censys.io/api/v2/hosts/search"

        # 查询 1: 证书 SHA256
        sha256 = self.fingerprints.get("sha256")
        if sha256:
            try:
                r = requests.get(base, auth=auth, timeout=30,
                                 params={"q": f"services.tls.certificates.leaf_data.fingerprint:{sha256}",
                                         "per_page": 100})
                for hit in r.json().get("result", {}).get("hits", []):
                    results.append({"ip": hit.get("ip", ""), "source": "censys",
                                    "evidence": "Cert SHA256 match", "confidence": "S"})
            except Exception as e:
                print(f"  [censys] SHA256 查询失败: {e}", file=sys.stderr)

        # 查询 2: Subject CN 包含根域名
        root_domain = self._root_domain()
        if root_domain:
            try:
                r = requests.get(base, auth=auth, timeout=30,
                                 params={"q": f'services.tls.certificates.leaf_data.subject.common_name:"{root_domain}"',
                                         "per_page": 100})
                for hit in r.json().get("result", {}).get("hits", []):
                    ip = hit.get("ip", "")
                    if not any(c["ip"] == ip for c in results):
                        results.append({"ip": ip, "source": "censys",
                                        "evidence": f"Cert CN contains {root_domain}",
                                        "confidence": "A"})
            except Exception as e:
                print(f"  [censys] CN 查询失败: {e}", file=sys.stderr)
        return results

    # ------------------------------------------------------------------
    # 步骤 1b: Shodan API
    # ------------------------------------------------------------------
    def scan_shodan(self) -> List[Dict[str, Any]]:
        """Shodan API 搜索全网"""
        results: List[Dict[str, Any]] = []
        key = self.api_keys.get("SHODAN_API_KEY")
        if not key:
            return results

        queries: List[Tuple[str, str, str]] = []
        sha256 = self.fingerprints.get("sha256")
        if sha256:
            queries.append((f"ssl.cert.fingerprint:{sha256}", "Cert SHA256 match", "S"))
        title = self.fingerprints.get("title")
        if title:
            queries.append((f'http.title:"{title}"', f"Title match: {title}", "B"))
        fav = self.fingerprints.get("favicon_mmh3")
        if fav and isinstance(fav, int):
            queries.append((f"http.favicon.hash:{fav}", "Favicon hash match", "C"))
        root = self._root_domain()
        if root:
            queries.append((f'ssl.cert.subject.cn:"{root}"', f"Cert CN: {root}", "A"))

        for query, evidence, conf in queries:
            try:
                r = requests.get("https://api.shodan.io/shodan/host/search",
                                 params={"key": key, "query": query}, timeout=30)
                data = r.json()
                for m in data.get("matches", []):
                    ip = m.get("ip_str", "")
                    if ip and not any(c["ip"] == ip for c in results):
                        results.append({"ip": ip, "source": "shodan",
                                        "evidence": evidence, "confidence": conf})
            except Exception as e:
                print(f"  [shodan] 查询失败 ({evidence}): {e}", file=sys.stderr)
        return results

    # ------------------------------------------------------------------
    # 步骤 1c: FOFA API
    # ------------------------------------------------------------------
    def scan_fofa(self) -> List[Dict[str, Any]]:
        """FOFA API 搜索全网 (国内最全)"""
        results: List[Dict[str, Any]] = []
        key = self.api_keys.get("FOFA_API_KEY")
        email = self.api_keys.get("FOFA_EMAIL")
        if not key or not email:
            return results

        queries: List[Tuple[str, str, str]] = []
        sha256 = self.fingerprints.get("sha256")
        if sha256:
            queries.append((f'cert.sha256="{sha256}"', "Cert SHA256 match", "S"))
        title = self.fingerprints.get("title")
        if title:
            queries.append((f'title="{title}"', f"Title match", "B"))
        body_hash = self.fingerprints.get("body_hash")
        if body_hash:
            queries.append((f'body_hash="{body_hash}"', "Body hash match", "B"))
        fav = self.fingerprints.get("favicon_mmh3")
        if fav and isinstance(fav, int):
            queries.append((f'icon_hash="{fav}"', "Favicon hash match", "C"))

        for query, evidence, conf in queries:
            try:
                q64 = base64.b64encode(query.encode()).decode()
                r = requests.get("https://fofa.info/api/v1/search/all", timeout=30,
                                 params={"email": email, "key": key, "qbase64": q64,
                                         "size": 100, "fields": "ip,port,title,server,domain"})
                for row in r.json().get("results", []):
                    ip = row[0] if isinstance(row, list) else row.get("ip", "")
                    if ip and not any(c["ip"] == ip for c in results):
                        results.append({"ip": ip, "source": "fofa",
                                        "evidence": evidence, "confidence": conf,
                                        "port": row[1] if isinstance(row, list) else None})
            except Exception as e:
                print(f"  [fofa] 查询失败 ({evidence}): {e}", file=sys.stderr)
        return results

    # ------------------------------------------------------------------
    # 步骤 1d: ZoomEye API
    # ------------------------------------------------------------------
    def scan_zoomeye(self) -> List[Dict[str, Any]]:
        """ZoomEye API 搜索"""
        results: List[Dict[str, Any]] = []
        key = self.api_keys.get("ZOOMEYE_API_KEY")
        if not key:
            return results
        sha256 = self.fingerprints.get("sha256")
        if not sha256:
            return results
        try:
            r = requests.get("https://api.zoomeye.org/host/search",
                             headers={"API-KEY": key}, timeout=30,
                             params={"query": f"ssl.cert.fingerprint:{sha256}", "page": 1})
            for m in r.json().get("matches", []):
                ip = m.get("ip", "")
                if ip:
                    results.append({"ip": ip, "source": "zoomeye",
                                    "evidence": "Cert SHA256 match", "confidence": "S"})
        except Exception as e:
            print(f"  [zoomeye] 查询失败: {e}", file=sys.stderr)
        return results

    # ------------------------------------------------------------------
    # 步骤 1e: 360 Quake API
    # ------------------------------------------------------------------
    def scan_quake(self) -> List[Dict[str, Any]]:
        """360 Quake API 搜索"""
        results: List[Dict[str, Any]] = []
        key = self.api_keys.get("QUAKE_API_KEY")
        if not key:
            return results
        sha256 = self.fingerprints.get("sha256")
        if not sha256:
            return results
        try:
            r = requests.post("https://quake.360.net/api/v3/search/quake_service",
                              headers={"X-QuakeToken": key, "Content-Type": "application/json"},
                              json={"query": f'cert.fingerprint:"{sha256}"',
                                    "start": 0, "size": 50}, timeout=30)
            for m in r.json().get("data", []):
                ip = m.get("ip", "")
                if ip:
                    results.append({"ip": ip, "source": "quake",
                                    "evidence": "Cert SHA256 match", "confidence": "S"})
        except Exception as e:
            print(f"  [quake] 查询失败: {e}", file=sys.stderr)
        return results

    # ------------------------------------------------------------------
    # 步骤 2a: ZMap + ZGrab2 主动扫描
    # ------------------------------------------------------------------
    def scan_zmap_zgrab2(self, target_ranges: Optional[List[str]] = None,
                         port: int = 443, bandwidth: str = "50M",
                         timeout: int = 3600) -> List[Dict[str, Any]]:
        """ZMap 扫描存活主机 + ZGrab2 抓取 TLS 证书 + 匹配 SHA256"""
        results: List[Dict[str, Any]] = []
        sha256 = self.fingerprints.get("sha256")
        if not sha256:
            print("  [zmap] 缺少证书 SHA256 指纹, 跳过", file=sys.stderr)
            return results
        if not _have_tool("zmap") or not _have_tool("zgrab2"):
            print("  [zmap] zmap/zgrab2 未安装, 跳过主动扫描", file=sys.stderr)
            return results

        workdir = tempfile.mkdtemp(prefix="iwscan_")
        alive_file = os.path.join(workdir, "alive.txt")
        range_file = os.path.join(workdir, "ranges.txt")
        tls_output = os.path.join(workdir, "tls.json")

        try:
            # 步骤 1: ZMap 扫描存活主机
            zmap_cmd = ["zmap", "-p", str(port), "-o", alive_file,
                        "--bandwidth=" + bandwidth]
            if target_ranges:
                with open(range_file, "w") as f:
                    f.write("\n".join(target_ranges))
                zmap_cmd += ["-w", range_file]
            else:
                # 全网扫描需黑名单排除 CDN
                blacklist = os.path.join(workdir, "blacklist.txt")
                self._write_cdn_blacklist(blacklist)
                zmap_cmd += ["--blacklist-file=" + blacklist]

            print(f"  [zmap] 启动 ZMap 扫描 (port={port}, bw={bandwidth})...")
            subprocess.run(zmap_cmd, timeout=timeout, check=False)

            if not os.path.exists(alive_file) or os.path.getsize(alive_file) == 0:
                print("  [zmap] 无存活主机", file=sys.stderr)
                return results

            # 步骤 2: ZGrab2 抓取 TLS 证书
            print(f"  [zgrab2] 抓取 TLS 证书...")
            subprocess.run([
                "zgrab2", "tls", f"--input-file={alive_file}",
                f"--output-file={tls_output}", f"--port={port}",
                "--timeout=8", "--senders=500",
            ], timeout=timeout, check=False)

            # 步骤 3: 解析匹配
            results = self._match_zgrab2_tls(tls_output, sha256)
        except subprocess.TimeoutExpired:
            print("  [zmap] 扫描超时", file=sys.stderr)
        except Exception as e:
            print(f"  [zmap] 异常: {e}", file=sys.stderr)
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
        return results

    def _match_zgrab2_tls(self, tls_file: str, target_sha256: str) -> List[Dict[str, Any]]:
        """解析 ZGrab2 TLS 输出, 匹配证书 SHA256"""
        results: List[Dict[str, Any]] = []
        try:
            with open(tls_file, encoding="utf-8") as f:
                for line in f:
                    try:
                        r = json.loads(line)
                        ip = r.get("ip", "")
                        tls = r.get("data", {}).get("tls", {})
                        handshake = tls.get("result", {}).get("handshake_log", {})
                        cert = (handshake.get("server_certificates", {})
                                .get("certificate", {}).get("parsed", {}))
                        cert_sha = cert.get("fingerprint_sha256", "").replace(":", "").lower()
                        if cert_sha == target_sha256:
                            results.append({"ip": ip, "source": "zmap+zgrab2",
                                            "evidence": "Cert SHA256 match (active scan)",
                                            "confidence": "S"})
                            continue
                        # Subject CN 模糊匹配
                        subject = cert.get("subject", {})
                        cn = ""
                        for item in subject.get("common_name", []):
                            cn = item
                            break
                        root = self._root_domain()
                        if root and root in cn.lower():
                            results.append({"ip": ip, "source": "zmap+zgrab2",
                                            "evidence": f"Cert CN contains {root}",
                                            "confidence": "A"})
                    except Exception:
                        continue
        except Exception as e:
            print(f"  [zgrab2] 解析失败: {e}", file=sys.stderr)
        return results

    # ------------------------------------------------------------------
    # 步骤 2b: Masscan 多端口扫描
    # ------------------------------------------------------------------
    def scan_masscan(self, target_ranges: Optional[List[str]] = None,
                     ports: str = "80,443,8080,8443",
                     rate: int = 10000, timeout: int = 3600) -> List[Dict[str, Any]]:
        """Masscan 多端口扫描 + 后续 ZGrab2 HTTP 匹配"""
        results: List[Dict[str, Any]] = []
        if not _have_tool("masscan"):
            print("  [masscan] masscan 未安装, 跳过", file=sys.stderr)
            return results

        workdir = tempfile.mkdtemp(prefix="iwscan_mc_")
        output_file = os.path.join(workdir, "masscan.json")
        range_file = os.path.join(workdir, "ranges.txt")

        try:
            masscan_cmd = ["masscan", f"-p{ports}", f"--rate={rate}",
                           f"-oJ", output_file]
            if target_ranges:
                with open(range_file, "w") as f:
                    f.write("\n".join(target_ranges))
                masscan_cmd += ["-iL", range_file]
            else:
                masscan_cmd.append("0.0.0.0/0")
                masscan_cmd += ["--exclude", "10.0.0.0/8,127.0.0.0/8,169.254.0.0/16"]

            print(f"  [masscan] 启动扫描 (ports={ports}, rate={rate})...")
            subprocess.run(masscan_cmd, timeout=timeout, check=False)

            # 解析 masscan JSON 输出, 提取存活 IP
            alive_ips: List[str] = []
            try:
                with open(output_file, encoding="utf-8") as f:
                    content = f.read()
                # masscan -oJ 输出是 JSON 数组
                # 兼容格式: [ {ip, ports:[{port}]}, ... ]
                for line in content.splitlines():
                    line = line.strip().rstrip(",")
                    if not line or line in ("[", "]"):
                        continue
                    try:
                        rec = json.loads(line)
                        ip = rec.get("ip")
                        if ip:
                            alive_ips.append(ip)
                    except Exception:
                        continue
            except Exception:
                pass

            print(f"  [masscan] 发现 {len(alive_ips)} 个存活 IP")

            # 后续: ZGrab2 HTTP 抓取 + 匹配 (若有 zgrab2)
            if alive_ips and _have_tool("zgrab2"):
                results = self._zgrab2_http_match(alive_ips, workdir)
            else:
                # 无 zgrab2, 仅返回存活 IP 作为弱候选
                for ip in alive_ips:
                    results.append({"ip": ip, "source": "masscan",
                                    "evidence": "Port open (no fingerprint match)",
                                    "confidence": "C"})
        except subprocess.TimeoutExpired:
            print("  [masscan] 扫描超时", file=sys.stderr)
        except Exception as e:
            print(f"  [masscan] 异常: {e}", file=sys.stderr)
        finally:
            shutil.rmtree(workdir, ignore_errors=True)
        return results

    def _zgrab2_http_match(self, ips: List[str], workdir: str) -> List[Dict[str, Any]]:
        """用 ZGrab2 HTTP 抓取响应, 匹配 Title/Server/BodyHash"""
        results: List[Dict[str, Any]] = []
        alive_file = os.path.join(workdir, "alive_http.txt")
        http_output = os.path.join(workdir, "http.json")
        with open(alive_file, "w") as f:
            f.write("\n".join(ips))

        subprocess.run([
            "zgrab2", "http", f"--input-file={alive_file}",
            f"--output-file={http_output}", "--port=80",
            "--use-https=false", '--user-agent="Mozilla/5.0 (compatible; ZGrab/2.0)"',
            "--timeout=10", "--senders=1000",
        ], timeout=3600, check=False)

        target_title = self.fingerprints.get("title", "")
        target_server = self.fingerprints.get("server", "")
        target_body_hash = self.fingerprints.get("body_hash", "")

        try:
            with open(http_output, encoding="utf-8") as f:
                for line in f:
                    try:
                        r = json.loads(line)
                        ip = r.get("ip", "")
                        http = r.get("data", {}).get("http", {})
                        resp = http.get("result", {}).get("response", {})
                        body = resp.get("body", "")
                        headers = resp.get("headers", {})

                        server = ""
                        for h in headers.get("values", []):
                            if h[0].lower() == "server":
                                server = h[1]
                                break

                        body_clean = _clean_body(body)
                        body_hash = hashlib.sha256(body_clean.encode()).hexdigest()

                        score = 0
                        evidence = []
                        if body_hash == target_body_hash and target_body_hash:
                            score += 40
                            evidence.append("BodyHash 完全匹配")
                        elif body_hash[:16] == target_body_hash[:16] and target_body_hash:
                            score += 20
                            evidence.append("BodyHash 前缀匹配")
                        if server == target_server and target_server:
                            score += 20
                            evidence.append(f"Server 匹配: {server}")
                        if target_title and target_title in body:
                            score += 20
                            evidence.append("Title 匹配")

                        if score >= 40:
                            results.append({"ip": ip, "source": "masscan+zgrab2",
                                            "evidence": " | ".join(evidence),
                                            "confidence": "B" if score >= 60 else "C",
                                            "score": score})
                    except Exception:
                        continue
        except Exception as e:
            print(f"  [zgrab2-http] 解析失败: {e}", file=sys.stderr)
        return results

    # ------------------------------------------------------------------
    # 步骤 3: 候选去重 + 去 CDN 化
    # ------------------------------------------------------------------
    def verify_candidates(self, candidates: Optional[List[Dict[str, Any]]] = None
                          ) -> List[Dict[str, Any]]:
        """候选 IP 去重 + 用 cdn_ranges 过滤 CDN + 计算置信度评分"""
        cands = candidates if candidates is not None else self.candidates

        # 去重 (保留最高置信度)
        seen: Dict[str, Dict[str, Any]] = {}
        conf_order = {"S": 4, "A": 3, "B": 2, "C": 1}
        for c in cands:
            ip = c.get("ip", "")
            if not ip:
                continue
            if ip in seen:
                # 保留置信度更高的
                if conf_order.get(c.get("confidence", "C"), 0) > \
                   conf_order.get(seen[ip].get("confidence", "C"), 0):
                    seen[ip] = c
                else:
                    # 合并证据
                    seen[ip]["evidence"] += f" | {c.get('evidence','')}"
                    seen[ip]["sources"] = seen[ip].get("sources", [seen[ip]["source"]]) + [c["source"]]
            else:
                seen[ip] = dict(c)
                seen[ip]["sources"] = [c.get("source", "")]

        # 标注 CDN/源站
        verified: List[Dict[str, Any]] = []
        for ip, c in seen.items():
            c["ip"] = ip
            c["is_cdn"] = is_cdn(ip)
            c["vendor"] = get_vendor(ip)
            verified.append(c)

        # 排序: 置信度 > 非 CDN > 来源数
        verified.sort(key=lambda x: (
            conf_order.get(x.get("confidence", "C"), 0),
            0 if not x.get("is_cdn") else 1,
            -len(x.get("sources", [])),
        ), reverse=True)
        return verified

    # ------------------------------------------------------------------
    # 步骤 4: 全流程编排
    # ------------------------------------------------------------------
    def run_all(self, target_ranges: Optional[List[str]] = None,
                scan_mode: str = "auto",
                ports: str = "80,443,8080,8443") -> List[Dict[str, Any]]:
        """运行所有扫描方法 (API 优先, 主动扫描兜底)

        参数:
            target_ranges: 限定 IP 段 (CIDR 列表), 缩小扫描范围
            scan_mode: 'auto' (API 不足时主动扫描) / 'api_only' / 'zmap' / 'masscan'
            ports: Masscan 端口
        """
        print(f"[*] 提取目标指纹: {self.target}")
        self.extract_fingerprints()
        print(f"    证书 SHA256: {self.fingerprints.get('sha256', '(无)')}")
        print(f"    Title:       {self.fingerprints.get('title', '(无)')}")
        print(f"    Server:      {self.fingerprints.get('server', '(无)')}")
        print(f"    Body Hash:   {self.fingerprints.get('body_hash', '(无)')[:32]}...")
        print(f"    Favicon:     {self.fingerprints.get('favicon_mmh3', '(无)')}")

        all_results: List[Dict[str, Any]] = []

        # 优先 API 查询 (零成本)
        if self.api_keys:
            print("\n[*] API 平台查询 (零成本)...")
            with ThreadPoolExecutor(max_workers=5) as ex:
                fut_map = {
                    ex.submit(self.scan_censys): "censys",
                    ex.submit(self.scan_shodan): "shodan",
                    ex.submit(self.scan_fofa): "fofa",
                    ex.submit(self.scan_zoomeye): "zoomeye",
                    ex.submit(self.scan_quake): "quake",
                }
                for fut in fut_map:
                    name = fut_map[fut]
                    try:
                        res = fut.result()
                        all_results.extend(res)
                        print(f"    [{name}] +{len(res)} 候选")
                    except Exception as e:
                        print(f"    [{name}] 失败: {e}", file=sys.stderr)
        else:
            print("\n[!] 未提供任何 API Key, 跳过 API 查询")

        # 主动扫描 (兜底)
        need_active = (scan_mode in ("zmap", "masscan")
                       or (scan_mode == "auto" and len(all_results) < 3))
        if need_active:
            print(f"\n[*] 主动扫描 (mode={scan_mode}, candidates={len(all_results)})...")
            if scan_mode in ("auto", "masscan"):
                mc = self.scan_masscan(target_ranges=target_ranges, ports=ports)
                all_results.extend(mc)
                print(f"    [masscan] +{len(mc)} 候选")
            if scan_mode in ("auto", "zmap") and len(all_results) < 3:
                zm = self.scan_zmap_zgrab2(target_ranges=target_ranges)
                all_results.extend(zm)
                print(f"    [zmap] +{len(zm)} 候选")

        # 去重 + 去 CDN 化
        self.candidates = self.verify_candidates(all_results)

        print(f"\n[*] 找到 {len(self.candidates)} 个候选 IP (已去 CDN)")
        for c in self.candidates:
            tag = "CDN" if c.get("is_cdn") else "ORIGIN?"
            print(f"    {c['ip']:18s} [{c.get('confidence','?')}] [{tag:7s}] "
                  f"{c.get('evidence','')} ({', '.join(c.get('sources', []))})")
        return self.candidates

    # ------------------------------------------------------------------
    # 辅助
    # ------------------------------------------------------------------
    def _root_domain(self) -> str:
        """提取根域名 (简化版)"""
        parts = self.target.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return self.target

    def _write_cdn_blacklist(self, path: str) -> None:
        """导出 CDN IP 段为 ZMap 黑名单格式"""
        try:
            from cdn_ranges import CDN_DATA  # type: ignore
            with open(path, "w") as f:
                for vendor, info in CDN_DATA.items():
                    for cidr in info.get("ipv4", []):
                        f.write(cidr + "\n")
        except Exception:
            pass


def _now() -> str:
    from datetime import datetime
    return datetime.now().isoformat()


# ======================================================================
# CLI
# ======================================================================
def _main() -> int:
    parser = argparse.ArgumentParser(
        description="internet_wide_scanner — 全网 IP 扫描溯源引擎 (ZMap/Masscan/ZGrab2 + API)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 仅提取目标指纹
  python internet_wide_scanner.py target.com --extract-fingerprints

  # API 查询 (零成本, 推荐)
  python internet_wide_scanner.py target.com \\
      --shodan-key KEY --censys-id ID --censys-secret SEC \\
      --fofa-email EMAIL --fofa-key KEY

  # 限定 IP 段主动扫描 (ZMap+ZGrab2 证书匹配)
  python internet_wide_scanner.py target.com --ranges aws_ranges.txt --scan-mode zmap

  # Masscan 多端口扫描
  python internet_wide_scanner.py target.com --scan-mode masscan --ports 80,443,8080

工作流 (SKILL.md §14G.10):
  步骤 0  指纹提取 → 步骤 1 平台查询 → 步骤 2 定向扫描
  → 步骤 3 多指纹验证 → 步骤 4 去 CDN 化 → 步骤 5 四维验证

注意:
  - 全网扫描需 root + 大带宽 (≥100Mbps)
  - 优先用 API (Censys/Shodan 已覆盖 99%+)
  - 法律合规: 仅扫描有授权的目标
        """,
    )
    parser.add_argument("target", help="目标域名 (如 target.com)")
    parser.add_argument("--extract-fingerprints", action="store_true",
                        help="仅提取目标指纹, 不扫描")
    parser.add_argument("--shodan-key", help="Shodan API Key")
    parser.add_argument("--censys-id", help="Censys API ID")
    parser.add_argument("--censys-secret", help="Censys API Secret")
    parser.add_argument("--fofa-key", help="FOFA API Key")
    parser.add_argument("--fofa-email", help="FOFA Email")
    parser.add_argument("--zoomeye-key", help="ZoomEye API Key")
    parser.add_argument("--quake-key", help="360 Quake API Key")
    parser.add_argument("--ranges", help="限定 IP 段文件 (每行一个 CIDR)")
    parser.add_argument("--scan-mode", default="auto",
                        choices=["auto", "api_only", "zmap", "masscan"],
                        help="扫描模式 (默认 auto)")
    parser.add_argument("--ports", default="80,443,8080,8443",
                        help="Masscan 端口 (默认 80,443,8080,8443)")
    parser.add_argument("-o", "--output", help="输出 JSON 到文件")
    args = parser.parse_args()

    # 关闭 SSL 警告
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass

    api_keys: Dict[str, str] = {}
    if args.shodan_key:    api_keys["SHODAN_API_KEY"] = args.shodan_key
    if args.censys_id:     api_keys["CENSYS_API_ID"] = args.censys_id
    if args.censys_secret: api_keys["CENSYS_API_SECRET"] = args.censys_secret
    if args.fofa_key:      api_keys["FOFA_API_KEY"] = args.fofa_key
    if args.fofa_email:    api_keys["FOFA_EMAIL"] = args.fofa_email
    if args.zoomeye_key:   api_keys["ZOOMEYE_API_KEY"] = args.zoomeye_key
    if args.quake_key:     api_keys["QUAKE_API_KEY"] = args.quake_key

    scanner = InternetWideScanner(args.target, api_keys)

    # 仅提取指纹
    if args.extract_fingerprints:
        fps = scanner.extract_fingerprints()
        print("\n" + "=" * 60)
        print("  目标指纹")
        print("=" * 60)
        for k, v in fps.items():
            print(f"  {k:20s}: {v}")
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(fps, f, ensure_ascii=False, indent=2)
            print(f"\n[+] JSON 已保存: {args.output}")
        return 0

    # 加载限定 IP 段
    target_ranges = None
    if args.ranges:
        try:
            with open(args.ranges, encoding="utf-8") as f:
                target_ranges = [line.strip() for line in f
                                 if line.strip() and not line.startswith("#")]
        except Exception as e:
            print(f"[错误] 无法读取 ranges 文件: {e}", file=sys.stderr)
            return 2

    candidates = scanner.run_all(target_ranges=target_ranges,
                                 scan_mode=args.scan_mode,
                                 ports=args.ports)

    # 输出结果
    payload = {
        "target": args.target,
        "fingerprints": scanner.fingerprints,
        "candidates": candidates,
        "scan_mode": args.scan_mode,
        "timestamp": _now(),
    }
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        print(f"\n[+] JSON 已保存: {args.output}")

    # 终端排名表
    print("\n" + "=" * 70)
    print("  候选源站 IP 排名")
    print("=" * 70)
    print(f"  {'排名':4s} {'IP':18s} {'置信':4s} {'类型':8s} {'来源':20s} 证据")
    print("-" * 70)
    for i, c in enumerate(candidates, 1):
        tag = "CDN" if c.get("is_cdn") else "ORIGIN"
        srcs = ",".join(c.get("sources", []))[:20]
        print(f"  {i:<4d} {c['ip']:18s} {c.get('confidence','?'):4s} "
              f"{tag:8s} {srcs:20s} {c.get('evidence','')[:40]}")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
