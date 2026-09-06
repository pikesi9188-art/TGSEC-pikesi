# tunnel-kit — 内网隧道与代理链

选型 → 生成命令 →（可选）装 chisel/frp。  
**仅授权/实验室**；生产劫持类隧道先问用户。

```bash
bash tools/tunnel-kit/install_tunnels.sh
python3 tools/tunnel-kit/tunnel_plan.py doctor
python3 tools/tunnel-kit/tunnel_plan.py recommend --have shell --egress http
python3 tools/tunnel-kit/tunnel_plan.py emit --kind chisel --attacker 攻击机IP --case <案卷>
```

模板：`templates/`（ssh / chisel / frp / ligolo 笔记）  
证据：`案卷/<案卷>/测绘/tunnel/`
