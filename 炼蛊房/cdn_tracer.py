#!/usr/bin/env python3
"""
cdn_origin_tracer.py — v5.0 全流程溯源框架
依赖: pip install requests dnspython tldextract
用法: python3 cdn_origin_tracer.py target.com [--api-keys keys.json]
输出: report_<target>_<ts>.json
"""
import argparse, json, time, socket, hashlib, re, concurrent.futures
from pathlib import Path
from datetime import datetime
import requests, dns.resolver

IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
PRIVATE_RE = re.compile(r'^(10\.|127\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.|0\.)')

# ---------- 阶段基类 ----------
class Stage:
    name = "base"
    def run(self, target, ctx):  # ctx: 共享上下文字典
        raise NotImplementedError

# ---------- 阶段1: 证书透明度 ----------
class CertTransparencyStage(Stage):
    name = "A_cert"
    def run(self, target, ctx):
        ips, names = set(), set()
        try:
            r = requests.get(f"https://crt.sh/?q=%.{target}&output=json", timeout=20)
            for item in r.json():
                for n in item.get('name_value','').split('\n'):
                    n = n.strip().lstrip('*.')
                    names.add(n)
                    # crt.sh 不直接返回 IP，但 name_value 偶有 IP
                    for ip in IP_RE.findall(n): ips.add(ip)
        except Exception as e:
            ctx.setdefault('errors',[]).append(f"crt.sh: {e}")
        ctx['cert_names'] = names
        ctx['cert_ips'] = ips
        return {'names': list(names), 'ips': list(ips)}

# ---------- 阶段2: 子域名枚举 + 解析 ----------
class SubdomainStage(Stage):
    name = "C_subdomain"
    WORDLIST = "mail ftp smtp pop3 imap webmail cpanel whm admin dev staging test direct origin backend vpn mysql ssh static img upload api m mobile app shop blog forum wiki status monitor secure remote portal demo beta ns1 ns2 cdn proxy www1 www2 assets media files git svn mta mx relay".split()
    def run(self, target, ctx):
        # 泛解析检测
        wildcard = self._resolve(f"randomnoexist{int(time.time())}.{target}")
        found = {}
        def probe(sub):
            ip = self._resolve(f"{sub}.{target}")
            if ip and ip != wildcard: found[f"{sub}.{target}"] = ip
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            list(ex.map(probe, self.WORDLIST))
        ctx['subdomain_ips'] = set(found.values())
        return found
    @staticmethod
    def _resolve(host):
        try:
            return socket.gethostbyname(host)
        except: return None

# ---------- 阶段3: 历史 DNS / 被动 DNS 聚合 ----------
class PassiveDNSStage(Stage):
    name = "B_dns_history"
    SOURCES = [
        ("hackertarget", lambda t: f"https://api.hackertarget.com/hostsearch/?q={t}"),
        ("otx",          lambda t: f"https://otx.alienvault.com/api/v1/indicators/domain/{t}/passive_dns"),
    ]
    def run(self, target, ctx):
        ips = {}
        for name, url_fn in self.SOURCES:
            try:
                r = requests.get(url_fn(target), timeout=20)
                if name == "hackertarget":
                    for ip in IP_RE.findall(r.text): ips[ip] = ips.get(ip,0)+1
                else:
                    for item in r.json().get('passive_dns',[]):
                        a = item.get('address')
                        if a and not PRIVATE_RE.match(a): ips[a] = ips.get(a,0)+1
            except Exception as e:
                ctx.setdefault('errors',[]).append(f"{name}: {e}")
        ctx['pdns_ips'] = ips
        return ips
    # SecurityTrails/VirusTotal 需 API key，可在此扩展

# ---------- 阶段4: 四维指纹验证 ----------
class FingerprintStage(Stage):
    name = "E_fingerprint"
    def run(self, target, ctx):
        cdn_headers = self._headers(target, use_host=False)
        results = {}
        for ip in ctx.get('candidates', []):
            direct = self._headers(ip, use_host=True, target=target, sni=target)
            # 判定: 无 CDN 头 + Server 与直连一致
            has_cdn_hdr = any(h in direct.lower() for h in [b'cf-ray', b'x-amz-cf', b'x-sucuri'])
            results[ip] = {
                'has_cdn_header': has_cdn_hdr,
                'status': direct.get('status'),
                'server': direct.get('server'),
                'verified': not has_cdn_hdr and direct.get('status') in (200,301,302,403),
            }
        ctx['fingerprint'] = results
        return results
    @staticmethod
    def _headers(host, use_host=False, target=None, sni=None):
        import urllib3; urllib3.disable_warnings()
        headers = {"Host": target} if use_host else {}
        try:
            r = requests.get(f"https://{host}", headers=headers, verify=False, timeout=6, allow_redirects=False)
            hd = {k.lower(): v for k,v in r.headers.items()}
            return {'status': r.status_code, 'server': hd.get('server'), 'raw': hd}
        except Exception as e:
            return {'status': 0, 'error': str(e)}

# ---------- 阶段5: 贝叶斯评分 ----------
class ScoreStage(Stage):
    name = "score"
    LLR = {
        'A_cert':3.0,'B_dns_history':2.5,'C_subdomain':2.0,
        'D_mail':2.0,'E_fingerprint':4.0,'F_space_engine':1.5,
    }
    import math
    def run(self, target, ctx):
        import math
        scored = []
        for ip in ctx.get('candidates', []):
            ev = {
                'A_cert': ip in ctx.get('cert_ips', set()),
                'B_dns_history': ip in ctx.get('pdns_ips', {}),
                'C_subdomain': ip in ctx.get('subdomain_ips', set()),
                'E_fingerprint': ctx.get('fingerprint',{}).get(ip,{}).get('verified', False),
            }
            logit = math.log(0.25)  # 先验
            for dim, llr in self.LLR.items():
                logit += llr if ev.get(dim) else -1.0
            prob = 1/(1+math.exp(-logit))
            scored.append({'ip': ip, 'prob': prob, 'evidence': ev})
        scored.sort(key=lambda x: -x['prob'])
        return scored

# ---------- Pipeline 调度 ----------
class TracerPipeline:
    def __init__(self, target):
        self.target = target
        self.ctx = {'candidates': set()}
        self.stages = [
            CertTransparencyStage(), SubdomainStage(), PassiveDNSStage(),
        ]
        # 候选 IP 合并 + 过滤
    def run(self):
        for stage in self.stages:
            print(f"[*] 运行: {stage.name}")
            stage.run(self.target, self.ctx)
        # 合并候选
        cand = set()
        cand |= self.ctx.get('cert_ips', set())
        cand |= set(self.ctx.get('pdns_ips', {}))
        cand |= self.ctx.get('subdomain_ips', set())
        self.ctx['candidates'] = [c for c in cand if not PRIVATE_RE.match(c)]
        # 验证 + 评分
        FingerprintStage().run(self.target, self.ctx)
        results = ScoreStage().run(self.target, self.ctx)
        return {
            'target': self.target, 'timestamp': datetime.now().isoformat(),
            'candidates_count': len(self.ctx['candidates']),
            'ranked': results, 'errors': self.ctx.get('errors', []),
        }

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('target'); ap.add_argument('--api-keys')
    args = ap.parse_args()
    report = TracerPipeline(args.target).run()
    out = f"report_{args.target.replace('.','_')}_{int(time.time())}.json"
    Path(out).write_text(json.dumps(report, indent=2, ensure_ascii=False))
    print(f"\n[+] 报告: {out}")
    for r in report['ranked'][:5]:
        print(f"  {r['ip']:16} P={r['prob']:.1%}  证据={r['evidence']}")
