#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ja3extract.py — TLS 服务端指纹提取器 (JA3S / JA4S + 证书指纹)
================================================================
源自 SKILL.md §11.1 「JA3/JA4 TLS客户端指纹」验证体系。

实现原理:
    1. 通过原始 socket 向目标发送一个标准化 ClientHello
    2. 解析服务端返回的 ServerHello, 提取:
       - TLS 版本 (record version + handshake version)
       - 选中的 Cipher Suite
       - 扩展列表 (按原始顺序)
       - 椭圆曲线 / 椭圆曲线点格式 (若存在)
    3. 按经典 JA3S 算法 (Salesforce 原版) 拼接字段并 MD5
    4. 按新 JA4S 算法 (FoxIO 2024) 生成 a_b_c_d 格式指纹
    5. 通过 subprocess 调用 openssl 抓取证书 SHA256 / 序列号 / Subject

用途 (CDN 溯源):
    - 对 CDN 节点提取 JA3S 指纹
    - 对候选源站 IP 提取 JA3S 指纹
    - 指纹一致 → 强烈证据表明同一后端 (LLR +3.0)

依赖:
    - 仅 Python 标准库 (socket / struct / hashlib / ssl / subprocess)
    - 可选 openssl (用于证书解析, subprocess 调用)

CLI:
    python ja3extract.py --target origin_ip:443
    python ja3extract.py --target 1.2.3.4:443 --sni example.com
    python ja3extract.py --compare cdn.example.com:443 1.2.3.4:443 --sni example.com

可被 cdn_tracer.py 导入使用:
    from ja3extract import extract_server_fingerprint, compare_fingerprints
"""
import argparse
import hashlib
import json
import socket
import ssl
import struct
import subprocess
import sys
from typing import Optional, Dict, Any, List, Tuple

# ======================================================================
# TLS 常量定义
# ======================================================================
TLS_CONTENT_TYPE_HANDSHAKE = 0x16
TLS_HANDSHAKE_SERVER_HELLO = 0x02
TLS_HANDSHAKE_CERTIFICATE = 0x0B

# 标准 ClientHello 使用的 Cipher Suites (覆盖现代浏览器集合)
# 按典型 Chrome 顺序排列, 用于触发服务端真实选型
DEFAULT_CIPHER_SUITES = [
    # TLS 1.3
    0x1301, 0x1302, 0x1303,
    # ECDHE-ECDSA
    0xC02B, 0xC02C, 0xC02F, 0xC030,
    # ECDHE-RSA
    0xC013, 0xC014, 0xC027, 0xC028,
    # RSA
    0x009E, 0x009F, 0x0033, 0x0039, 0x002F, 0x0035,
    # 兜底
    0x00FF,
]

# ClientHello 扩展 (按 Chrome 典型顺序)
# 每项: (type, data_bytes)
def _build_default_extensions(sni: Optional[str]) -> List[Tuple[int, bytes]]:
    """构造一组标准扩展, 触发服务端完整响应"""
    exts = []
    # SNI (server_name)
    if sni:
        sni_bytes = sni.encode("idna")
        sni_list = struct.pack(">BH", 0x00, len(sni_bytes)) + sni_bytes
        exts.append((0x0000, sni_list))
    # supported_versions (TLS 1.3, 1.2, 1.1, 1.0)
    sv = struct.pack(">BHHHH", 8, 0x0304, 0x0303, 0x0302, 0x0301)
    exts.append((0x002B, sv))
    # supported_groups (x25519, secp256r1, secp384r1)
    groups = struct.pack(">BH", 0x001D, 0x0017, 0x0018)
    exts.append((0x000A, struct.pack(">H", 4) + groups))
    # signature_algorithms
    sig_algs = b"\x00\x0c\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01"
    exts.append((0x000D, sig_algs))
    # key_share (x25519 占位)
    exts.append((0x0033, struct.pack(">HH", 0x001D, 0x0020) + b"\x00" * 32))
    # session_ticket
    exts.append((0x0023, b""))
    # ec_point_formats
    exts.append((0x000B, b"\x01\x00"))
    # renegotiation_info
    exts.append((0xFF01, b"\x00"))
    # ALPN (h2, http/1.1)
    alpn = struct.pack(">BB", 2, 0x02) + b"\x02h2\x08http/1.1"
    exts.append((0x0010, struct.pack(">H", len(alpn)) + alpn))
    return exts


# ======================================================================
# ClientHello 构造
# ======================================================================
def build_client_hello(sni: Optional[str] = None,
                       ciphers: Optional[List[int]] = None) -> bytes:
    """构造一个标准 ClientHello 字节流 (含 TLS record 头)"""
    ciphers = ciphers or DEFAULT_CIPHER_SUITES
    # Client Version (TLS 1.2)
    version = b"\x03\x03"
    # Random (32 字节, 固定值便于复现)
    random_bytes = b"\x00" * 32
    # Session ID (空)
    session_id = b"\x00"
    # Cipher Suites
    cipher_data = struct.pack(">H", len(ciphers) * 2) + b"".join(struct.pack(">H", c) for c in ciphers)
    # Compression Methods (null)
    compression = b"\x01\x00"
    # Extensions
    exts = _build_default_extensions(sni)
    ext_blocks = b""
    for etype, edata in exts:
        ext_blocks += struct.pack(">HH", etype, len(edata)) + edata
    extensions = struct.pack(">H", len(ext_blocks)) + ext_blocks

    # ClientHello body
    body = version + random_bytes + session_id + cipher_data + compression + extensions
    # Handshake header (type=ClientHello, length=3 bytes)
    handshake = struct.pack(">B", 0x01) + _uint24(len(body)) + body
    # TLS record header
    record = struct.pack(">BHH", TLS_CONTENT_TYPE_HANDSHAKE, 0x0301, len(handshake)) + handshake
    return record


def _uint24(n: int) -> bytes:
    """3 字节大端整数"""
    return struct.pack(">I", n)[1:]


def _read_uint24(b: bytes) -> int:
    return (b[0] << 16) | (b[1] << 8) | b[2]


# ======================================================================
# TLS 记录读取 + ServerHello 解析
# ======================================================================
def _recv_tls_records(sock: socket.socket, max_bytes: int = 16384,
                      timeout: float = 8.0) -> bytes:
    """循环读取, 直到拿到完整 ServerHello + 部分证书"""
    sock.settimeout(timeout)
    buf = b""
    try:
        while len(buf) < max_bytes:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            # 收到 Certificate 记录即可停止 (足够提取 ServerHello)
            if b"\x0b\x00\x00" in buf:
                # 粗略判断已含证书握手头
                break
    except socket.timeout:
        pass
    return buf


def _parse_extensions(data: bytes) -> List[Dict[str, Any]]:
    """解析扩展块, 返回 [{type, type_hex, data_hex, data_len}]"""
    exts = []
    i = 0
    while i + 4 <= len(data):
        etype = struct.unpack(">H", data[i:i + 2])[0]
        elen = struct.unpack(">H", data[i + 2:i + 4])[0]
        i += 4
        if i + elen > len(data):
            break
        edata = data[i:i + elen]
        exts.append({
            "type": etype,
            "type_hex": f"0x{etype:04x}",
            "data_hex": edata.hex(),
            "data_len": elen,
        })
        i += elen
    return exts


def parse_server_hello(buf: bytes) -> Optional[Dict[str, Any]]:
    """从原始 TLS 字节流解析 ServerHello, 返回结构化指纹信息"""
    offset = 0
    # 遍历 record 层
    while offset + 5 <= len(buf):
        ctype, ver, rlen = struct.unpack(">BHH", buf[offset:offset + 5])
        if ctype != TLS_CONTENT_TYPE_HANDSHAKE:
            offset += 5 + rlen
            continue
        record_end = offset + 5 + rlen
        if record_end > len(buf):
            record_end = len(buf)
        record_body = buf[offset + 5:record_end]
        # 在 record body 中找 ServerHello
        hoff = 0
        while hoff + 4 <= len(record_body):
            ht = record_body[hoff]
            hl = _read_uint24(record_body[hoff + 1:hoff + 4])
            if hoff + 4 + hl > len(record_body):
                break
            hb = record_body[hoff + 4:hoff + 4 + hl]
            if ht == TLS_HANDSHAKE_SERVER_HELLO:
                return _decode_server_hello(hb)
            hoff += 4 + hl
        offset = record_end
    return None


def _decode_server_hello(body: bytes) -> Dict[str, Any]:
    """解码 ServerHello body"""
    info: Dict[str, Any] = {}
    if len(body) < 2:
        return info
    pos = 0
    # Handshake version
    hs_version = struct.unpack(">H", body[pos:pos + 2])[0]
    pos += 2
    info["handshake_version"] = hs_version
    info["handshake_version_str"] = _version_to_str(hs_version)
    # Random (32 bytes)
    pos += 32
    # Session ID
    if pos >= len(body):
        return info
    sid_len = body[pos]
    pos += 1 + sid_len
    # Cipher Suite
    if pos + 2 > len(body):
        return info
    cipher = struct.unpack(">H", body[pos:pos + 2])[0]
    pos += 2
    info["cipher_suite"] = cipher
    info["cipher_suite_hex"] = f"0x{cipher:04x}"
    # Compression method
    if pos >= len(body):
        return info
    pos += 1  # 1 byte compression
    # Extensions
    if pos + 2 > len(body):
        info["extensions"] = []
        return info
    ext_len = struct.unpack(">H", body[pos:pos + 2])[0]
    pos += 2
    ext_block = body[pos:pos + ext_len]
    info["extensions"] = _parse_extensions(ext_block)
    # 提取 supported_versions (如果存在, 覆盖 handshake_version)
    for e in info["extensions"]:
        if e["type"] == 0x002B and len(e["data_hex"]) >= 4:
            sv_bytes = bytes.fromhex(e["data_hex"])
            # 1 byte length + 2 byte selected version
            if len(sv_bytes) >= 3:
                real_ver = struct.unpack(">H", sv_bytes[1:3])[0]
                info["real_version"] = real_ver
                info["real_version_str"] = _version_to_str(real_ver)
    return info


def _version_to_str(v: int) -> str:
    return {
        0x0301: "TLS 1.0",
        0x0302: "TLS 1.1",
        0x0303: "TLS 1.2",
        0x0304: "TLS 1.3",
    }.get(v, f"Unknown(0x{v:04x})")


# ======================================================================
# JA3S / JA4S 计算
# ======================================================================
def compute_ja3s(server_hello: Dict[str, Any]) -> Dict[str, Any]:
    """计算经典 JA3S 指纹 (服务端版本)

    格式: TLSVersion,Cipher,Extensions,EllipticCurves,EC_PointFormats
    指纹 = MD5(上述字符串)
    """
    # 1. TLS Version (使用 real_version 若存在, 否则 handshake_version)
    version = server_hello.get("real_version") or server_hello.get("handshake_version", 0)
    # 2. Cipher Suite
    cipher = server_hello.get("cipher_suite", 0)
    # 3. Extensions (排除 GREASE)
    ext_types = []
    for e in server_hello.get("extensions", []):
        t = e["type"]
        if not _is_grease(t):
            ext_types.append(str(t))
    # 4. & 5. ServerHello 一般不含 curves/point_formats, 留空
    fields = [
        str(version),
        str(cipher),
        "-".join(ext_types),
        "",  # elliptic curves
        "",  # EC point formats
    ]
    ja3_str = ",".join(fields)
    ja3_hash = hashlib.md5(ja3_str.encode()).hexdigest()
    return {
        "ja3s_string": ja3_str,
        "ja3s_md5": ja3_hash,
        "version": version,
        "cipher": cipher,
        "extensions": ext_types,
    }


def compute_ja4s(server_hello: Dict[str, Any]) -> Dict[str, Any]:
    """计算 JA4S 指纹 (FoxIO 2024 新规范, 服务端版本)

    格式: q_<ALPN>_<Cipher>_<Extensions>
      q       = 's' (server)
      ALPN    = 'h2' / 'h1' / '00' (无 ALPN)
      Cipher  = 4 位 hex
      Extensions = 4 位 hex 串联 (排除 GREASE)
    """
    # ALPN
    alpn_val = "00"
    for e in server_hello.get("extensions", []):
        if e["type"] == 0x0010 and len(e["data_hex"]) >= 4:
            try:
                data = bytes.fromhex(e["data_hex"])
                # ALPN list: 2 bytes list_len, 然后每个 protocol: 1 byte len + bytes
                p = 0
                if len(data) >= 2:
                    list_len = struct.unpack(">H", data[p:p + 2])[0]
                    p += 2
                    # 取第一个 protocol
                    if p < len(data):
                        plen = data[p]
                        p += 1
                        proto = data[p:p + plen].decode("ascii", errors="ignore")
                        if proto == "h2":
                            alpn_val = "h2"
                        elif proto.startswith("http/1"):
                            alpn_val = "h1"
                        break
            except Exception:
                pass

    # Cipher
    cipher = server_hello.get("cipher_suite", 0)
    cipher_hex = f"{cipher:04x}"

    # Extensions (排除 GREASE, 转为 4 位 hex 串联)
    ext_str = "".join(f"{e['type']:04x}"
                      for e in server_hello.get("extensions", [])
                      if not _is_grease(e["type"]))

    # Version prefix
    real_ver = server_hello.get("real_version") or server_hello.get("handshake_version", 0)
    if real_ver == 0x0304:
        ver_prefix = "t"  # TLS 1.3
    elif real_ver == 0x0303:
        ver_prefix = "q"  # TLS 1.2
    elif real_ver == 0x0302:
        ver_prefix = "p"  # TLS 1.1
    else:
        ver_prefix = "o"

    ja4s = f"{ver_prefix}_{alpn_val}_{cipher_hex}_{ext_str}"
    ja4s_hash = hashlib.sha256(ja4s.encode()).hexdigest()[:32]
    return {
        "ja4s": ja4s,
        "ja4s_sha256_trunc": ja4s_hash,
    }


def _is_grease(val: int) -> bool:
    """判断是否为 GREASE 值 (Google 随机扩展)"""
    return (val & 0x0F0F) == 0x0A0A and val in {
        0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A,
        0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
    }


# ======================================================================
# 证书指纹提取 (openssl 子进程)
# ======================================================================
def extract_cert_fingerprint(host: str, port: int,
                             sni: Optional[str] = None,
                             timeout: int = 10) -> Dict[str, Any]:
    """通过 openssl s_client 抓取证书指纹

    返回: {sha256, sha1, serial, subject_cn, issuer_cn, not_before, not_after, spki_sha256}
    """
    result: Dict[str, Any] = {"available": False}
    sni = sni or host
    try:
        # 步骤 1: 抓取证书 PEM
        s_client_cmd = [
            "openssl", "s_client", "-connect", f"{host}:{port}",
            "-servername", sni, "-showcerts",
        ]
        s_client = subprocess.run(
            s_client_cmd,
            input=b"",
            capture_output=True,
            timeout=timeout,
        )
        pem_data = s_client.stdout
        if b"BEGIN CERTIFICATE" not in pem_data:
            return result

        # 步骤 2: 解析证书字段
        x509_cmd = [
            "openssl", "x509", "-noout",
            "-fingerprint", "-sha256",
            "-fingerprint", "-sha1",
            "-serial", "-subject", "-issuer", "-dates",
            "-pubkey",
        ]
        x509 = subprocess.run(
            x509_cmd,
            input=_first_cert_pem(pem_data),
            capture_output=True,
            timeout=5,
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
            elif line.startswith("subject="):
                result["subject"] = line.split("=", 1)[1]
                # 提取 CN
                if "CN=" in line:
                    result["subject_cn"] = line.split("CN=", 1)[1].split(",")[0].split("/")[0]
            elif line.startswith("issuer="):
                result["issuer"] = line.split("=", 1)[1]
                if "CN=" in line:
                    result["issuer_cn"] = line.split("CN=", 1)[1].split(",")[0].split("/")[0]
            elif line.startswith("notBefore="):
                result["not_before"] = line.split("=", 1)[1]
            elif line.startswith("notAfter="):
                result["not_after"] = line.split("=", 1)[1]

        # 步骤 3: 计算 SPKI (Subject Public Key Info) SHA256
        pubkey_block = _extract_pubkey_pem(out)
        if pubkey_block:
            spki = subprocess.run(
                ["openssl", "pkey", "-pubin", "-outform", "DER"],
                input=pubkey_block.encode(),
                capture_output=True,
                timeout=5,
            )
            if spki.returncode == 0 and spki.stdout:
                # 注: 严格 SPKI 应包含算法标识, 这里用公钥 DER 做简化指纹
                result["pubkey_sha256"] = hashlib.sha256(spki.stdout).hexdigest()
        result["available"] = True
    except FileNotFoundError:
        result["error"] = "openssl 未安装"
    except subprocess.TimeoutExpired:
        result["error"] = "openssl 超时"
    except Exception as e:
        result["error"] = f"openssl 异常: {e}"
    return result


def _first_cert_pem(pem_data: bytes) -> bytes:
    """从 s_client -showcerts 输出中提取第一张证书 PEM"""
    start = pem_data.find(b"-----BEGIN CERTIFICATE-----")
    end = pem_data.find(b"-----END CERTIFICATE-----", start)
    if start == -1 or end == -1:
        return b""
    return pem_data[start:end + len(b"-----END CERTIFICATE-----")] + b"\n"


def _extract_pubkey_pem(x509_out: str) -> str:
    """从 x509 -pubkey 输出中提取 PUBLIC KEY PEM 块"""
    start = x509_out.find("-----BEGIN PUBLIC KEY-----")
    end = x509_out.find("-----END PUBLIC KEY-----", start)
    if start == -1 or end == -1:
        return ""
    return x509_out[start:end + len("-----END PUBLIC KEY-----")] + "\n"


# ======================================================================
# 主接口: extract_server_fingerprint
# ======================================================================
def extract_server_fingerprint(target: str,
                               sni: Optional[str] = None,
                               timeout: float = 8.0,
                               with_cert: bool = True) -> Dict[str, Any]:
    """提取目标服务端完整 TLS 指纹

    参数:
        target: 形如 "1.2.3.4:443" 或 "example.com:8443"
        sni:    SNI 域名 (默认 None, 表示不发 SNI)
        timeout: socket 读取超时 (秒)
        with_cert: 是否同时用 openssl 提取证书指纹

    返回: {
        'target', 'sni',
        'server_hello': {...},
        'ja3s': {...}, 'ja4s': {...},
        'cert': {...},
        'raw_extensions_count',
    }
    """
    if ":" in target:
        host, port_str = target.rsplit(":", 1)
        port = int(port_str)
    else:
        host, port = target, 443

    result: Dict[str, Any] = {
        "target": target,
        "sni": sni,
        "host": host,
        "port": port,
    }

    # 1. 发送 ClientHello 并捕获 ServerHello
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        try:
            ch = build_client_hello(sni=sni)
            sock.sendall(ch)
            raw = _recv_tls_records(sock, timeout=timeout)
        finally:
            sock.close()

        if not raw:
            result["error"] = "未收到任何响应 (连接可能被重置)"
            return result

        sh = parse_server_hello(raw)
        if not sh:
            result["error"] = "无法解析 ServerHello (目标可能非 TLS 服务)"
            return result

        result["server_hello"] = sh
        result["ja3s"] = compute_ja3s(sh)
        result["ja4s"] = compute_ja4s(sh)
        result["raw_extensions_count"] = len(sh.get("extensions", []))
    except socket.timeout:
        result["error"] = f"连接超时 ({host}:{port})"
        return result
    except ConnectionRefusedError:
        result["error"] = f"连接被拒绝 ({host}:{port})"
        return result
    except OSError as e:
        result["error"] = f"网络异常: {e}"
        return result

    # 2. 证书指纹 (openssl)
    if with_cert:
        result["cert"] = extract_cert_fingerprint(host, port, sni=sni, timeout=int(timeout))

    return result


# ======================================================================
# 指纹对比 (CDN 节点 vs 候选源站)
# ======================================================================
def compare_fingerprints(fp_a: Dict[str, Any], fp_b: Dict[str, Any]) -> Dict[str, Any]:
    """对比两份服务端指纹, 返回差异/一致报告

    用于: CDN 节点 JA3S 与候选源站 JA3S 对比, 一致 → 强证据
    """
    report: Dict[str, Any] = {"match": False, "score": 0, "details": []}

    if fp_a.get("error") or fp_b.get("error"):
        report["error"] = "至少一方提取失败, 无法对比"
        return report

    ja3s_a = fp_a.get("ja3s", {}).get("ja3s_md5")
    ja3s_b = fp_b.get("ja3s", {}).get("ja3s_md5")
    ja4s_a = fp_a.get("ja4s", {}).get("ja4s")
    ja4s_b = fp_b.get("ja4s", {}).get("ja4s")
    cert_a = fp_a.get("cert", {}).get("sha256")
    cert_b = fp_b.get("cert", {}).get("sha256")

    score = 0
    if ja3s_a and ja3s_b and ja3s_a == ja3s_b:
        score += 35
        report["details"].append({"dim": "JA3S", "match": True, "value": ja3s_a})
    else:
        report["details"].append({"dim": "JA3S", "match": False,
                                  "a": ja3s_a, "b": ja3s_b})

    if ja4s_a and ja4s_b and ja4s_a == ja4s_b:
        score += 25
        report["details"].append({"dim": "JA4S", "match": True, "value": ja4s_a})
    else:
        report["details"].append({"dim": "JA4S", "match": False,
                                  "a": ja4s_a, "b": ja4s_b})

    if cert_a and cert_b and cert_a == cert_b:
        score += 40
        report["details"].append({"dim": "CertSHA256", "match": True, "value": cert_a})
    else:
        report["details"].append({"dim": "CertSHA256", "match": False,
                                  "a": cert_a, "b": cert_b})

    report["score"] = score
    report["match"] = score >= 60
    return report


# ======================================================================
# CLI
# ======================================================================
def _print_fingerprint(fp: Dict[str, Any], label: str = "") -> None:
    """彩色化输出单条指纹"""
    if label:
        print(f"\n{'=' * 60}\n  {label}\n{'=' * 60}")
    if fp.get("error"):
        print(f"  [失败] {fp['error']}")
        return
    sh = fp.get("server_hello", {})
    ja3s = fp.get("ja3s", {})
    ja4s = fp.get("ja4s", {})
    cert = fp.get("cert", {})

    print(f"  目标:       {fp.get('target')}")
    print(f"  SNI:        {fp.get('sni') or '(无)'}")
    print(f"  TLS 版本:   {sh.get('real_version_str') or sh.get('handshake_version_str')}")
    print(f"  Cipher:     {sh.get('cipher_suite_hex')}")
    print(f"  扩展数:     {fp.get('raw_extensions_count', 0)}")
    print(f"  JA3S MD5:   {ja3s.get('ja3s_md5')}")
    print(f"  JA3S 串:    {ja3s.get('ja3s_string')}")
    print(f"  JA4S:       {ja4s.get('ja4s')}")
    print(f"  JA4S hash:  {ja4s.get('ja4s_sha256_trunc')}")
    if cert.get("available"):
        print(f"  证书 SHA256: {cert.get('sha256')}")
        print(f"  证书序列号:  {cert.get('serial')}")
        print(f"  Subject CN:  {cert.get('subject_cn', '(无)')}")
        print(f"  Issuer CN:   {cert.get('issuer_cn', '(无)')}")
        print(f"  有效期:      {cert.get('not_before')} → {cert.get('not_after')}")
    elif cert.get("error"):
        print(f"  证书:        [跳过] {cert['error']}")


def _main() -> int:
    parser = argparse.ArgumentParser(
        description="ja3extract — TLS 服务端 JA3S/JA4S 指纹提取器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python ja3extract.py --target 1.2.3.4:443 --sni example.com
  python ja3extract.py --compare cdn.example.com:443 1.2.3.4:443 --sni example.com
        """,
    )
    parser.add_argument("--target", "-t", help="目标地址 host:port (单点提取模式)")
    parser.add_argument("--compare", nargs=2, metavar=("ENDPOINT_A", "ENDPOINT_B"),
                        help="对比两个端点指纹 (A=CDN节点, B=候选源站)")
    parser.add_argument("--sni", help="SNI 域名 (默认不发 SNI)")
    parser.add_argument("--timeout", type=float, default=8.0, help="socket 超时 (秒)")
    parser.add_argument("--no-cert", action="store_true", help="跳过证书提取 (仅指纹)")
    parser.add_argument("-o", "--output", help="输出 JSON 到文件")
    args = parser.parse_args()

    out_payload: Dict[str, Any] = {}

    if args.compare:
        a, b = args.compare
        print(f"[*] 提取端点 A: {a}")
        fp_a = extract_server_fingerprint(a, sni=args.sni,
                                          timeout=args.timeout,
                                          with_cert=not args.no_cert)
        _print_fingerprint(fp_a, label="端点 A (CDN 节点)")

        print(f"\n[*] 提取端点 B: {b}")
        fp_b = extract_server_fingerprint(b, sni=args.sni,
                                          timeout=args.timeout,
                                          with_cert=not args.no_cert)
        _print_fingerprint(fp_b, label="端点 B (候选源站)")

        print(f"\n{'=' * 60}\n  指纹对比结果\n{'=' * 60}")
        cmp = compare_fingerprints(fp_a, fp_b)
        for d in cmp.get("details", []):
            tag = "MATCH" if d["match"] else "DIFF"
            val = d.get("value", "{} \u2260 {}".format(d.get("a"), d.get("b")))
            print(f"  [{tag}] {d['dim']}: {val}")
        print(f"\n  综合评分: {cmp.get('score', 0)}/100")
        if cmp.get("match"):
            print("  判定: 指纹一致 → 强烈证据表明同一后端 (LLR +3.0)")
        elif cmp.get("score", 0) > 0:
            print("  判定: 部分一致 → 需补充其他证据")
        else:
            print("  判定: 指纹不一致 → 排除同一后端")
        out_payload = {"endpoint_a": fp_a, "endpoint_b": fp_b, "compare": cmp}

    elif args.target:
        print(f"[*] 提取目标指纹: {args.target}")
        fp = extract_server_fingerprint(args.target, sni=args.sni,
                                        timeout=args.timeout,
                                        with_cert=not args.no_cert)
        _print_fingerprint(fp, label="服务端 TLS 指纹")
        out_payload = fp

    else:
        parser.print_help()
        return 1

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(out_payload, f, ensure_ascii=False, indent=2)
        print(f"\n[+] JSON 已保存: {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
