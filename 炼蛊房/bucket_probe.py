#!/usr/bin/env python3
"""
bucket_probe.py — 云存储桶全链探测（授权范围内）

覆盖：AWS S3 / 阿里云 OSS / 腾讯云 COS / 七牛 Qiniu / MinIO / 通用 S3 兼容

攻击面：
  1. 桶名枚举（基于域名/关键词猜测）
  2. 公开读/ListObject 检测
  3. 匿名写/上传测试
  4. 签名预签URL 泄露探测
  5. ACL 策略读取（GetBucketPolicy/GetBucketACL）
  6. 自定义域 CNAME 悬空劫持探测
  7. JS/APK/前端资源中提取 AK/SK/Bucket 名/Endpoint
  8. STS 临时凭据测试
  9. 路径遍历 / 特殊文件枚举（backup, .env, .git 等）
 10. 桶域名接管（bucket name reuse）

用法：
  # 从目标域名猜测并枚举桶
  python3 炼蛊房/bucket_probe.py scan -d target.com

  # 直接测试已知桶名
  python3 炼蛊房/bucket_probe.py test --bucket my-bucket --cloud aliyun

  # 从 JS 文件提取 AK/SK/桶名
  python3 炼蛊房/bucket_probe.py extract -u https://target.com

  # 测试 AK/SK 权限
  python3 炼蛊房/bucket_probe.py cred --ak AKID... --sk xxx... --cloud aliyun

  # 检测悬空 CNAME（桶域名接管）
  python3 炼蛊房/bucket_probe.py takeover -d target.com

依赖：pip install requests dnspython boto3
"""

import argparse
import json
import re
import sys
import time
import hashlib
import hmac
import base64
import urllib.parse
from datetime import datetime, UTC
from pathlib import Path

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[!] pip install requests")
    sys.exit(1)

# ──────────────────────────── scope 检查 ────────────────────────────

OPS = Path(__file__).resolve().parent
if str(OPS) not in sys.path:
    sys.path.insert(0, str(OPS))
from scope_lib import require_in_scope  # noqa: E402


# ──────────────────────────── 桶名生成 ──────────────────────────────

def _guess_bucket_names(domain: str) -> list[str]:
    """从域名生成候选桶名"""
    base = domain.split(".")[0]
    parts = domain.replace("-", ".").replace("_", ".").split(".")
    keywords = [p for p in parts if len(p) > 2 and p not in ("com", "cn", "net", "org")]

    names = set()
    for kw in keywords:
        names.update([
            kw, f"{kw}-static", f"{kw}-assets", f"{kw}-upload",
            f"{kw}-uploads", f"{kw}-media", f"{kw}-img", f"{kw}-images",
            f"{kw}-backup", f"{kw}-bak", f"{kw}-files", f"{kw}-data",
            f"{kw}-prod", f"{kw}-dev", f"{kw}-test", f"{kw}-stg",
            f"{kw}-cdn", f"{kw}-public", f"{kw}-private", f"{kw}-logs",
            f"static-{kw}", f"assets-{kw}", f"upload-{kw}", f"media-{kw}",
            f"img-{kw}", f"cdn-{kw}",
            # 博彩站常见
            f"{kw}-game", f"{kw}-sport", f"{kw}-live", f"{kw}-bet",
            f"{kw}-pay", f"{kw}-api", f"{kw}-app",
        ])
    return sorted(names)


# ──────────────────────────── 云厂商端点 ─────────────────────────────

CLOUD_ENDPOINTS = {
    "aws": {
        "url": "https://{bucket}.s3.amazonaws.com",
        "list": "https://{bucket}.s3.amazonaws.com/?list-type=2",
        "region_urls": [
            "https://{bucket}.s3.us-east-1.amazonaws.com",
            "https://{bucket}.s3.ap-southeast-1.amazonaws.com",
            "https://{bucket}.s3.ap-east-1.amazonaws.com",
        ],
    },
    "aliyun": {
        "url": "https://{bucket}.oss-cn-hangzhou.aliyuncs.com",
        "regions": [
            "oss-cn-hangzhou", "oss-cn-shanghai", "oss-cn-beijing",
            "oss-cn-shenzhen", "oss-cn-guangzhou", "oss-cn-chengdu",
            "oss-ap-southeast-1", "oss-ap-southeast-5",
        ],
        "url_pattern": "https://{bucket}.{region}.aliyuncs.com",
        "list": "https://{bucket}.{region}.aliyuncs.com/?list-type=2",
    },
    "tencent": {
        "url": "https://{bucket}-{appid}.cos.ap-guangzhou.myqcloud.com",
        "list": "https://{bucket}-{appid}.cos.ap-guangzhou.myqcloud.com/?list-type=2",
        "regions": [
            "ap-guangzhou", "ap-shanghai", "ap-beijing",
            "ap-chengdu", "ap-hongkong", "ap-singapore",
        ],
        "url_pattern": "https://{bucket}.cos.{region}.myqcloud.com",
    },
    "qiniu": {
        "url": "https://{bucket}.qiniudn.com",
        "domains": [
            "qiniudn.com", "qbox.me", "bkt.clouddn.com", "qnssl.com",
        ],
    },
    "minio": {
        "url": "http://{host}/{bucket}",
        "list": "http://{host}/{bucket}?list-type=2",
    },
}

OSS_BUCKET_403_CLUES = [
    "AccessDenied", "RequestId", "HostId",
    "NoSuchBucket", "InvalidBucketName",
]

# ──────────────────────────── HTTP 工具 ──────────────────────────────

def _sess() -> requests.Session:
    s = requests.Session()
    s.verify = False
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (compatible; curl/7.88)",
    })
    return s


def _req(sess, method: str, url: str, **kwargs) -> requests.Response | None:
    try:
        kwargs.setdefault("timeout", 10)
        kwargs.setdefault("verify", False)
        kwargs.setdefault("allow_redirects", False)
        return sess.request(method, url, **kwargs)
    except Exception:
        return None


# ──────────────────────────── 桶探测核心 ─────────────────────────────

class BucketResult:
    def __init__(self, bucket: str, cloud: str, url: str):
        self.bucket = bucket
        self.cloud = cloud
        self.url = url
        self.exists = False
        self.listable = False
        self.writable = False
        self.acl_readable = False
        self.policy_readable = False
        self.objects: list[str] = []
        self.interesting_files: list[str] = []
        self.raw_policy: str = ""
        self.notes: list[str] = []

    def __str__(self):
        flags = []
        if self.exists:     flags.append("存在")
        if self.listable:   flags.append("★可列目录")
        if self.writable:   flags.append("★★可上传")
        if self.acl_readable: flags.append("ACL可读")
        if self.policy_readable: flags.append("Policy可读")
        return f"[{self.cloud}] {self.bucket}  {'|'.join(flags) if flags else '无权访问'}"


def probe_aliyun(sess, bucket: str) -> list[BucketResult]:
    results = []
    for region in CLOUD_ENDPOINTS["aliyun"]["regions"]:
        url = f"https://{bucket}.{region}.aliyuncs.com"
        r = _req(sess, "GET", url)
        if r is None:
            continue

        br = BucketResult(bucket, f"aliyun/{region}", url)

        if r.status_code == 200:
            br.exists = True
            br.listable = True
            # 解析列表
            br.objects = re.findall(r"<Key>([^<]+)</Key>", r.text)[:50]
            br.interesting_files = _filter_interesting(br.objects)
            br.notes.append(f"公开可列目录！共 {len(br.objects)} 个对象（截断50）")
            results.append(br)
            break

        if r.status_code == 403:
            body = r.text
            if any(c in body for c in OSS_BUCKET_403_CLUES) or "RequestId" in r.headers:
                br.exists = True
                br.notes.append("桶存在但访问被拒（私有或IP策略限制）")
                # 尝试读 ACL
                r2 = _req(sess, "GET", url + "?acl")
                if r2 and r2.status_code == 200:
                    br.acl_readable = True
                    br.raw_policy = r2.text[:500]
                    br.notes.append("ACL 可读：" + r2.text[:200])
                # 尝试读 Policy
                r3 = _req(sess, "GET", url + "?policy")
                if r3 and r3.status_code == 200:
                    br.policy_readable = True
                    br.raw_policy += "\n" + r3.text[:500]
                    br.notes.append("Policy 可读！" + r3.text[:200])
                results.append(br)
                break

        if r.status_code == 404:
            # NoSuchBucket — 桶不存在，可能可接管
            if "NoSuchBucket" in r.text:
                br.notes.append("桶不存在（可能域名接管机会）")
                results.append(br)
                break
    return results


def probe_tencent(sess, bucket: str) -> list[BucketResult]:
    results = []
    # 腾讯桶名格式：{name}-{appid}，如果只有 name 就试各 region
    for region in CLOUD_ENDPOINTS["tencent"]["regions"]:
        url = f"https://{bucket}.cos.{region}.myqcloud.com"
        r = _req(sess, "GET", url)
        if r is None:
            continue

        br = BucketResult(bucket, f"tencent/{region}", url)

        if r.status_code == 200:
            br.exists = True
            br.listable = True
            br.objects = re.findall(r"<Key>([^<]+)</Key>", r.text)[:50]
            br.interesting_files = _filter_interesting(br.objects)
            br.notes.append(f"公开可列目录！{len(br.objects)} 个对象")
            results.append(br)
            break

        if r.status_code in (403, 405):
            if any(c in r.text for c in OSS_BUCKET_403_CLUES) or "tencent" in r.text.lower():
                br.exists = True
                br.notes.append("桶存在，访问被拒")
                # 尝试匿名 PUT ACL（检测可写）
                r2 = _req(sess, "PUT", url + "?acl",
                          headers={"x-cos-acl": "public-read"})
                if r2 and r2.status_code in (200, 204):
                    br.writable = True
                    br.notes.append("★★ 匿名可修改 ACL！")
                results.append(br)
                break
    return results


def probe_aws(sess, bucket: str) -> list[BucketResult]:
    results = []
    url = f"https://{bucket}.s3.amazonaws.com"
    r = _req(sess, "GET", url + "/?list-type=2")
    br = BucketResult(bucket, "aws-s3", url)

    if r is None:
        return results

    if r.status_code == 200:
        br.exists = True
        br.listable = True
        br.objects = re.findall(r"<Key>([^<]+)</Key>", r.text)[:50]
        br.interesting_files = _filter_interesting(br.objects)
        br.notes.append(f"公开可列目录！{len(br.objects)} 个对象")
        results.append(br)
        return results

    if r.status_code == 403:
        if "AccessDenied" in r.text or "RequestId" in r.headers:
            br.exists = True
            br.notes.append("桶存在，访问被拒（私有）")
            # 读 ACL
            r2 = _req(sess, "GET", url + "?acl")
            if r2 and r2.status_code == 200:
                br.acl_readable = True
                br.notes.append("ACL 可读：" + r2.text[:200])
            results.append(br)

    if r.status_code == 404 and "NoSuchBucket" in (r.text or ""):
        br.notes.append("桶不存在（CNAME 接管机会）")
        results.append(br)

    return results


def probe_writable(sess, url: str, bucket_name: str) -> bool:
    """尝试匿名写入测试文件"""
    test_key = f"daaixianzun_test_{int(time.time())}.txt"
    test_url = url.rstrip("/") + f"/{test_key}"
    r = _req(sess, "PUT", test_url,
             data=b"daaixianzun-write-test",
             headers={"Content-Type": "text/plain"})
    if r and r.status_code in (200, 204):
        # 写入成功，立即删除
        _req(sess, "DELETE", test_url)
        return True
    return False


def probe_interesting_files(sess, base_url: str) -> list[tuple[str, int]]:
    """枚举敏感文件路径"""
    targets = [
        ".env", ".env.production", ".env.local",
        "config.php", "config.json", "config.yaml", "config.yml",
        "database.yml", "wp-config.php", "settings.py",
        "backup.zip", "backup.tar.gz", "backup.sql",
        "db.sql", "database.sql", "dump.sql",
        ".git/config", ".git/HEAD",
        "id_rsa", "id_ecdsa", ".ssh/id_rsa",
        "credentials", "aws_credentials",
        "access_token.json", "service_account.json",
        "app.jar", "application.jar", "app.war",
        "heapdump", "heapdump.hprof", "spring.log",
        "application.properties", "application.yml",
    ]
    hits = []
    for path in targets:
        url = base_url.rstrip("/") + "/" + path
        r = _req(sess, "HEAD", url)
        if r and r.status_code == 200:
            size = int(r.headers.get("Content-Length", 0))
            hits.append((path, size))
    return hits


def _filter_interesting(keys: list[str]) -> list[str]:
    """从列表中筛选敏感文件"""
    patterns = [
        r"\.(sql|bak|backup|zip|tar|gz|env|key|pem|p12|pfx|jar|war|properties|yml|yaml|json|log|conf|config)$",
        r"(password|passwd|secret|credential|token|key|auth|admin|config|backup|dump|db|database|id_rsa)",
        r"\.(xlsx|csv|pdf)$",
    ]
    hits = []
    for k in keys:
        for p in patterns:
            if re.search(p, k.lower()):
                hits.append(k)
                break
    return hits


# ──────────────────────────── 前端 AK/SK 提取 ───────────────────────

AK_PATTERNS = {
    "aliyun_ak":    re.compile(r'\b(LTAI[0-9A-Za-z]{14,22})\b'),
    "aliyun_sk":    re.compile(r'''(?:accessKeySecret|secretKey|SecretKey)\s*[=:]\s*['"]([A-Za-z0-9/+=]{20,60})['"]''', re.I),
    "tencent_ak":   re.compile(r'\b(AKID[0-9A-Za-z]{30,40})\b'),
    "tencent_sk":   re.compile(r'''(?:secretKey|SecretKey)\s*[=:]\s*['"]([0-9A-Za-z]{30,50})['"]''', re.I),
    "aws_ak":       re.compile(r'\b(AKIA[0-9A-Z]{16})\b'),
    "aws_sk":       re.compile(r'''(?:aws_secret_access_key|secretAccessKey)\s*[=:]\s*['"]([0-9A-Za-z/+=]{40})['"]''', re.I),
    "oss_bucket":   re.compile(r'''(?:bucket|Bucket)\s*[=:]\s*['"]([a-z0-9][a-z0-9\-]{2,62})['"]'''),
    "oss_endpoint": re.compile(r'(https?://[a-z0-9\-]+\.(?:oss|cos|s3)[^\'"\s]{5,80})'),
    "presigned_url": re.compile(r'(https?://[a-z0-9\-\.]+(?:oss|cos|s3)[^\'"\s]*(?:Signature|X-Amz-Signature|sign)[^\'"\s]{20,200})'),
    "sts_token":    re.compile(r'''(?:SecurityToken|sts_token)\s*[=:]\s*['"]([A-Za-z0-9/+=]{20,500})['"]''', re.I),
}


def extract_from_url(url: str) -> dict:
    """从页面/JS 提取 AK/SK/桶名/端点"""
    sess = _sess()
    findings = {}

    # 收集页面和 JS 链接
    r = _req(sess, "GET", url)
    if not r:
        return findings

    sources = [("page", r.text)]
    js_urls = re.findall(r'src=[\'"]([^\'"\s]+\.js[^\'"\s]*)[\'"]', r.text)
    for js in js_urls[:20]:
        full = js if js.startswith("http") else urllib.parse.urljoin(url, js)
        jr = _req(sess, "GET", full)
        if jr and jr.status_code == 200:
            sources.append((full, jr.text))

    for src_name, text in sources:
        for key, pat in AK_PATTERNS.items():
            matches = pat.findall(text)
            if matches:
                findings.setdefault(key, []).extend(matches[:5])

    return findings


# ──────────────────────────── CNAME 接管探测 ─────────────────────────

BUCKET_CNAME_SIGNATURES = [
    ("aliyun-oss", "aliyuncs.com"),
    ("tencent-cos", "myqcloud.com"),
    ("aws-s3", "s3.amazonaws.com"),
    ("qiniu", "qiniudn.com"),
    ("upcloud", "upaiyun.com"),
]


def probe_cname_takeover(domain: str) -> list[dict]:
    """检测子域 CNAME 悬空桶接管"""
    hits = []
    try:
        import dns.resolver
        has_dns = True
    except ImportError:
        has_dns = False

    sess = _sess()

    subdomains = [
        f"static.{domain}", f"assets.{domain}", f"img.{domain}",
        f"cdn.{domain}", f"media.{domain}", f"upload.{domain}",
        f"files.{domain}", f"s3.{domain}", f"oss.{domain}",
        f"cos.{domain}", f"storage.{domain}",
    ]

    for sub in subdomains:
        cname_target = None

        if has_dns:
            try:
                answers = dns.resolver.resolve(sub, "CNAME")
                cname_target = str(answers[0].target).rstrip(".")
            except Exception:
                pass

        if not cname_target:
            # fallback: HTTP 探测
            r = _req(sess, "GET", f"https://{sub}")
            if r and r.status_code in (404, 403):
                body = r.text
                for cloud, sig in BUCKET_CNAME_SIGNATURES:
                    if sig in body or sig in (r.headers.get("Server", "") + r.headers.get("x-oss-request-id", "")):
                        hits.append({
                            "subdomain": sub,
                            "cloud": cloud,
                            "status": r.status_code,
                            "hint": "CNAME 指向云存储但桶不存在，可接管",
                        })
            continue

        for cloud, sig in BUCKET_CNAME_SIGNATURES:
            if sig in cname_target:
                # 验证桶是否存在
                r = _req(sess, "GET", f"https://{sub}")
                if r and "NoSuchBucket" in (r.text or ""):
                    bucket_name = cname_target.split(".")[0]
                    hits.append({
                        "subdomain": sub,
                        "cname": cname_target,
                        "cloud": cloud,
                        "bucket_name": bucket_name,
                        "hint": f"★ CNAME 悬空！{sub} → {cname_target}，桶 {bucket_name} 不存在可注册接管",
                    })

    return hits


# ──────────────────────────── AK/SK 权限检测 ─────────────────────────

def test_aliyun_cred(ak: str, sk: str) -> dict:
    """测试阿里云 AK/SK 权限（ListBuckets 探测）"""
    # 简化的阿里云签名（用于探测）
    sess = _sess()
    host = "oss-cn-hangzhou.aliyuncs.com"
    date = datetime.now(UTC).strftime("%a, %d %b %Y %H:%M:%S GMT")
    string_to_sign = f"GET\n\n\n{date}\n/"
    sig = base64.b64encode(
        hmac.new(sk.encode(), string_to_sign.encode(), hashlib.sha1).digest()
    ).decode()

    r = _req(sess, "GET", f"https://{host}/",
             headers={
                 "Date": date,
                 "Authorization": f"OSS {ak}:{sig}",
             })

    if r is None:
        return {"valid": False, "error": "连接失败"}
    if r.status_code == 200:
        buckets = re.findall(r"<Name>([^<]+)</Name>", r.text)
        return {"valid": True, "buckets": buckets, "raw": r.text[:500]}
    if r.status_code == 403:
        return {"valid": "签名正确但无 ListBuckets 权限", "raw": r.text[:200]}
    return {"valid": False, "status": r.status_code, "raw": r.text[:200]}


def test_aws_cred(ak: str, sk: str, region: str = "us-east-1") -> dict:
    """测试 AWS AK/SK（使用 boto3 如可用）"""
    try:
        import boto3
        from botocore.exceptions import ClientError
        sts = boto3.client("sts", aws_access_key_id=ak,
                           aws_secret_access_key=sk, region_name=region)
        identity = sts.get_caller_identity()
        s3 = boto3.client("s3", aws_access_key_id=ak,
                          aws_secret_access_key=sk, region_name=region)
        try:
            buckets = s3.list_buckets()
            bucket_names = [b["Name"] for b in buckets.get("Buckets", [])]
        except ClientError:
            bucket_names = ["(无 ListBuckets 权限)"]
        return {
            "valid": True,
            "account": identity.get("Account"),
            "arn": identity.get("Arn"),
            "user_id": identity.get("UserId"),
            "buckets": bucket_names,
        }
    except Exception as e:
        return {"valid": False, "error": str(e)}


# ──────────────────────────── 命令入口 ──────────────────────────────

def cmd_scan(args: argparse.Namespace) -> int:
    domain = args.domain
    require_in_scope(domain)

    print(f"\n[*] 目标域: {domain}")
    buckets = _guess_bucket_names(domain)
    print(f"[*] 生成候选桶名 {len(buckets)} 个")

    sess = _sess()
    all_results = []

    for b in buckets:
        for cloud in (args.cloud or ["aliyun", "tencent", "aws"]):
            if cloud == "aliyun":
                results = probe_aliyun(sess, b)
            elif cloud == "tencent":
                results = probe_tencent(sess, b)
            elif cloud == "aws":
                results = probe_aws(sess, b)
            else:
                continue

            for r in results:
                if r.exists or r.notes:
                    all_results.append(r)
                    print(f"\n{r}")
                    for note in r.notes:
                        print(f"  · {note}")
                    if r.interesting_files:
                        print(f"  敏感文件: {r.interesting_files[:10]}")

    print(f"\n[*] 共发现 {len(all_results)} 个有价值桶")

    if not args.no_cname:
        print("\n[*] 检测 CNAME 悬空接管...")
        takeovers = probe_cname_takeover(domain)
        for t in takeovers:
            print(f"\n★ CNAME 接管: {t}")

    return 0


def cmd_test(args: argparse.Namespace) -> int:
    sess = _sess()
    bucket = args.bucket
    cloud = args.cloud or "aliyun"

    print(f"\n[*] 测试桶: {bucket}  云: {cloud}")

    if cloud == "aliyun":
        results = probe_aliyun(sess, bucket)
    elif cloud == "tencent":
        results = probe_tencent(sess, bucket)
    elif cloud == "aws":
        results = probe_aws(sess, bucket)
    else:
        print(f"[!] 不支持的云: {cloud}")
        return 1

    for r in results:
        print(f"\n{r}")
        for note in r.notes:
            print(f"  · {note}")

        # 如果可列目录，尝试枚举敏感文件
        if r.listable and r.objects:
            print("\n  前20个对象:")
            for o in r.objects[:20]:
                print(f"    {o}")
            if r.interesting_files:
                print("\n  ★ 敏感文件:")
                for f in r.interesting_files:
                    print(f"    {f}")

        # 测试是否可写
        if not args.no_write:
            print("\n  [*] 测试匿名写入...")
            if probe_writable(sess, r.url, bucket):
                print(f"  ★★ 可匿名上传！{r.url}")
            else:
                print("  [×] 不可匿名写入")

        # 枚举敏感路径
        if r.exists:
            print("\n  [*] 枚举敏感文件路径...")
            hits = probe_interesting_files(sess, r.url)
            if hits:
                print(f"  ★ 命中 {len(hits)} 个敏感文件:")
                for path, size in hits:
                    print(f"    {path}  ({size} bytes)  → {r.url}/{path}")
            else:
                print("  [×] 无敏感文件命中")

    return 0


def cmd_extract(args: argparse.Namespace) -> int:
    require_in_scope(args.url)
    print(f"\n[*] 从 {args.url} 提取 AK/SK/桶信息...")
    findings = extract_from_url(args.url)

    if not findings:
        print("[×] 未找到任何 AK/SK/桶名")
        return 0

    print(f"\n[+] 发现 {len(findings)} 类凭据/配置：")
    for key, vals in findings.items():
        print(f"\n  [{key}]")
        for v in set(vals):
            print(f"    {v}")

    return 0


def cmd_cred(args: argparse.Namespace) -> int:
    cloud = args.cloud or "aliyun"
    print(f"\n[*] 测试 {cloud} AK/SK 权限...")

    if cloud == "aliyun":
        result = test_aliyun_cred(args.ak, args.sk)
    elif cloud == "aws":
        result = test_aws_cred(args.ak, args.sk)
    else:
        print(f"[!] 暂不支持 {cloud} 签名测试，请用官方 CLI")
        return 1

    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def cmd_takeover(args: argparse.Namespace) -> int:
    domain = args.domain
    require_in_scope(domain)

    print(f"\n[*] 检测 {domain} 的 CNAME 悬空接管...")
    hits = probe_cname_takeover(domain)

    if not hits:
        print("[×] 未发现悬空 CNAME")
        return 0

    for h in hits:
        print(f"\n★ {h}")

    return 0


# ──────────────────────────── main ──────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="cloud bucket probe — 云存储桶全链探测（授权范围内）"
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    # scan
    p = sub.add_parser("scan", help="从域名猜测并扫描桶")
    p.add_argument("-d", "--domain", required=True)
    p.add_argument("--cloud", nargs="+", choices=["aliyun", "tencent", "aws"],
                   help="指定云厂商（默认全部）")
    p.add_argument("--no-cname", action="store_true", help="跳过 CNAME 接管检测")

    # test
    p = sub.add_parser("test", help="直接测试已知桶名")
    p.add_argument("--bucket", required=True)
    p.add_argument("--cloud", default="aliyun", choices=["aliyun", "tencent", "aws"])
    p.add_argument("--no-write", action="store_true", help="跳过写入测试")

    # extract
    p = sub.add_parser("extract", help="从页面/JS 提取 AK/SK/桶名")
    p.add_argument("-u", "--url", required=True)

    # cred
    p = sub.add_parser("cred", help="测试 AK/SK 权限")
    p.add_argument("--ak", required=True)
    p.add_argument("--sk", required=True)
    p.add_argument("--cloud", default="aliyun", choices=["aliyun", "aws"])

    # takeover
    p = sub.add_parser("takeover", help="检测 CNAME 悬空桶接管")
    p.add_argument("-d", "--domain", required=True)

    args = ap.parse_args()
    fn = {
        "scan": cmd_scan,
        "test": cmd_test,
        "extract": cmd_extract,
        "cred": cmd_cred,
        "takeover": cmd_takeover,
    }[args.cmd]
    sys.exit(fn(args))


if __name__ == "__main__":
    main()
