---
name: 巡伤
description: >-
  大爱仙尊·漏洞扫描与自动化安全测试全栈/Nmap/Nessus/OpenVAS/Nuclei/Acunetix/Burp Suite/2026最新扫描技术/AI驱动漏洞发现/持
  续安全扫描/DAST/SAST/IAST
---

# security-scanning（大爱仙尊）

目标须在 `授权范围`。本库已有专链时专卡赢。

## 真源

- 长文：`智道藏书/旁支传承/skills/security-scanning/SKILL.md`
- 手法：`传承/薄青·岁岁索命.md`
- 工具：`python3 炼蛊房/core_web_surface_probe.py --help`
- 路由：`python3 炼蛊房/shizhan_pack_route.py --name security-scanning`

---

长文超过 1800 行，作业时 Read 真源全文，不要凭记忆。

# 漏洞扫描与自动化安全测试 — 实战技能手册 v3.0

> **适用范围**: 企业安全团队 / 红蓝对抗 / DevSecOps 流水线 / 合规审计 / 云原生安全
> **最后更新**: 2026年7月
> **覆盖工具**: Nmap, Nessus, OpenVAS, Nuclei, Acunetix, Burp Suite Pro 2026, ZAP, Semgrep, CodeQL, SonarQube, Trivy, Prowler, ScoutSuite, Kube-Bench, Kube-Hunter, Masscan, ZMap

---

## 目录

1. [§1 网络扫描 (Network Scanning)](#1-网络扫描-network-scanning)
2. [§2 Web应用扫描 (Web Application Scanning)](#2-web应用扫描-web-application-scanning)
3. [§3 漏洞扫描 (Vulnerability Scanning)](#3-漏洞扫描-vulnerability-scanning)
4. [§4 模板驱动扫描 (Template-Based Scanning)](#4-模板驱动扫描-template-based-scanning)
5. [§5 静态应用安全测试 (SAST & Code Analysis)](#5-静态应用安全测试-sast--code-analysis)
6. [§6 动态与交互式扫描 (DAST & IAST)](#6-动态与交互式扫描-dast--iast)
7. [§7 容器与云安全扫描 (Container & Cloud Scanning)](#7-容器与云安全扫描-container--cloud-scanning)
8. [§8 AI驱动扫描 (AI-Driven Scanning)](#8-ai驱动扫描-ai-driven-scanning)
9. [§9 持续安全 (Continuous Security)](#9-持续安全-continuous-security)
10. [§10 扫描自动化与编排 (Scan Automation & Orchestration)](#10-扫描自动化与编排-scan-automation--orchestration)

---

## §1 网络扫描 (Network Scanning)

### 1.1 概述与核心原理

网络扫描是安全测试的基础环节，用于发现目标网络中的存活主机、开放端口、运行服务及其版本信息。2026年的网络扫描技术已从传统的IPv4 TCP/UDP扫描扩展到IPv6大规模扫描、云环境虚拟网络扫描、容器网络命名空间扫描以及服务网格（Service Mesh）层面的流量分析。核心技术栈包括：Nmap 7.95+、Masscan 1.3+、ZMap 4.0+、RustScan 2.3+ 以及云原生扫描工具（如 Azure Network Scanner、AWS VPC Reachability Analyzer）。

网络扫描的核心挑战在2026年有了新的维度：一是IPv6地址空间巨大（/64子网即有18,446,744,073,709,551,616个地址），传统全端口扫描不再可行，需要基于DNS反向区域、证书透明度日志（Certificate Transparency Logs）、BGP路由表等情报源进行目标缩减；二是云环境中的动态IP、弹性网卡、安全组、NACL等使得扫描面持续变化，需要结合云API进行资产发现后再扫描；三是容器网络中，Pod网络命名空间与主机网络命名空间隔离，需要特权容器或节点级扫描能力。

### 1.2 Nmap 核心扫描技术 (2026版)

Nmap 7.95 在2026年引入了多项新特性：支持HTTP/3服务发现、QUIC协议指纹识别、基于eBPF的内核级快速SYN扫描、以及改进的TLS 1.3指纹库。以下为实战命令集：

```bash
# 基础主机发现 — ICMP Echo + TCP SYN Ping + UDP Ping + ARP Ping
nmap -sn -PE -PS80,443,22,8080,8443 -PU161,53,123 -n 192.168.1.0/24

# 快速SYN扫描（使用eBPF加速，2026新特性）
nmap -sS -T4 --ebpf --min-rate 5000 --max-retries 1 -p- 10.0.0.0/8

# 完整TCP端口扫描 + 服务版本 + 操作系统检测 + NSE脚本
nmap -sS -sV -sC -O -p- --script-timeout 60s -oA full_scan 192.168.1.100

# UDP Top 1000端口扫描（UDP扫描慢，需限制端口范围）
nmap -sU -sV --top-ports 1000 --max-retries 2 -T4 -oA udp_scan 192.168.1.100

# IPv6网络扫描（使用-E选项指定源接口）
nmap -6 -sS -sV -sC -p 1-65535 --min-rate 3000 -oA ipv6_scan 2001:db8::/120

# 防火墙/IDS规避技术组合
nmap -sS -f --mtu 24 --data-length 128 --source-port 53 \
  -D RND:10 --randomize-hosts -T2 --max-retries 3 \
  -oA evasive_scan 192.168.1.100

# 云环境元数据端点探测（AWS/Azure/GCP/阿里云/腾讯云）
nmap --script http-meta-data-api \
  --script-args "aws,azure,gcp,alibaba,tencent" \
  -p 80,443,8080,8443,169.254.169.254 10.0.0.0/16
```

### 1.3 Nmap Scripting Engine (NSE) 实战

NSE是Nmap最强大的扩展能力，2026年NSE脚本库已超过600个脚本。以下为关键脚本分类与实战：

```bash
# 漏洞检测脚本组
nmap --script vuln -sV -p 1-10000 192.168.1.0/24

# 认证暴力破解检测
nmap --script auth --script-args "userdb=users.txt,passdb=passwords.txt" \
  -p 22,21,23,3389,5900 192.168.1.100

# SSL/TLS安全评估（2026年支持TLS 1.3和QUIC/HTTP3）
nmap --script ssl-enum-ciphers,ssl-cert,ssl-dh-params,ssl-heartbleed \
  --script-args "tls1.3,http3" -p 443,8443,465,993,995 192.168.1.100

# 数据库发现与信息收集
nmap --script "mysql-*,ms-sql-*,mongodb-*,redis-*,cassandra-*" \

…（其余见长文）
