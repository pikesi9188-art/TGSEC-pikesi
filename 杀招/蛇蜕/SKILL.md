---
name: 蛇蜕
description: >-
  Nuitka / PyInstaller 授权包认族、列 TOC、抽 auth 模块名。
  触发：Nuitka、PyInstaller、PYZ、onefile、pyc 逆向。
  网络验证/卡密接着 net-license-crack。
---

# Python 打包逆向（大爱仙尊）

授权本地样本。授权内默认打到 **L2**：TOC/串里出现 license/auth/fndata。

| 档 | 成立 | 不算 |
|----|------|------|
| L1 | 认出 PyInstaller MAGIC 或 Nuitka onefile | 只 file 出 PE |
| L2 | TOC 或嵌入 `.py` 名带 auth/license | 没列名就交下一张 |
| L3 | 解出源码后假认证被客户端吃 | 本卡不负责补丁（交卡密卡） |

PyInstaller cookie：`MEI\x0c\x0b\x0a\x0b\x0e`，尾 24 字节解 `pkg_len/toc_off/toc_len/pyver`。

## 立刻跑

```bash
python3 炼蛊房/py_pack_reverse.py drive --path <样本> --case <案>
python3 炼蛊房/py_pack_reverse.py list --path <样本>
python3 炼蛊房/net_license_probe.py drive --path <样本> --case <案>
```

产物：`案卷/py_pack/surface.json`。

## 六步

```text
① drive 认 kind=pyinstaller|nuitka
② list 看 py_names / authish
③ 有 checkLicense / fndata → net_license_probe
④ 假认证 serve 只绑 127.0.0.1
⑤ Electron asar 不走本卡
⑥ Unity / IL2CPP 走 client-crack-cheat
```

## 交接

| 认到 | 走 |
|------|----|
| 卡密 / 天盾 / 假认证 | `net-license-crack` |
| Electron | `thick-client` |
| 外挂 / IL2CPP | `client-crack-cheat` |

## 真源

- 手法：`传承/专项探府.md`
- 探针：`炼蛊房/py_pack_reverse.py`
