# pwn-kit — 二进制作业基础

通用 ELF 初筛（保护位 / 敏感字符串 / ROP 摘要）。  
Node/.node/BPP 专用链仍走 `杀招/bpp-node-exploit-chain`。

```bash
source scripts/arsenal-env.sh
python3 tools/pwn-kit/pwn_triage.py doctor
python3 tools/pwn-kit/pwn_triage.py triage --bin ./vuln --case <案卷>
python3 tools/pwn-kit/pwn_triage.py gadgets --bin ./vuln --case <案卷>
```

证据：`案卷/<案卷>/测绘/pwn/`
