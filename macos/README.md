# QQ macOS 机器码 (guid) 逆向工具

全部逻辑逆向自 macOS x86_64 版 `wrapper.node`(QQ 7.0.2 / 2026-09-24)。
Windows / Linux 实现不同, 别混用这套。

## 结论

```
guid(16 字节) = MD5( machine_id[8 字节] || sn 字符串 )
```

* `machine_id` 优先从 `<数据目录>/msf/machineid-info` 里 **TEA 解密** 读出;
  读不到就回退成主网卡 MAC: `machine_id = MAC(6 字节) + 00 00`
* `sn` 优先取 `/dev/disk0` 的序列号, 失败回退 `IOPlatformSerialNumber`
* TEA 密钥 = `IOPlatformUUID` 字符串的前 16 个字节(按大端解释)

## 相关文件

* `machineid-info` — 内容 `be32(8)+machine_id[8] + be32(len)+sn`, **TEA 容器加密**
* `machine-info` — 内容 `be32(len)+[MAC(6)+00 00]`, **TEA 容器加密**
* `machine-guid` — 16 字节 guid, **明文**

两个 info 文件都走同一套 "容器" 封装: 不是整段 ECB, 而是每 8 字节一块的链式结构。

## 容器 / TEA 规格

记明文块 `X_i`, 中间块 `P_i`, 密文块 `C_i`, 初始 `C_-1 = P_-1 = 0`:

```
P_i = X_i ^ C_(i-1)
C_i = E(P_i) ^ P_(i-1)
```

明文流布局:

```
[head] [v8 个随机字节] [2 个随机字节] [payload] [7 个 0x00]
head = (rand & 0xF8) | v8
v8   = (-(len(payload) + 10)) % 8
```

TEA: 16 轮, delta `0x9E3779B9`, 密钥与数据都按 **大端** 处理。

## 用法

```bash
python3 qq_guid.py selftest        # 自检 (TEA / 容器 / 字段)
python3 qq_guid.py info            # 打印本机 UUID / SN / MAC / 密钥

# 解密真实的 machineid-info
python3 qq_guid.py decrypt \
  "$HOME/Library/Containers/com.tencent.qq/Data/Library/Application Support/QQ/global/nt_data/msf/machineid-info"

# 直接从 machineid-info 反推 guid
python3 qq_guid.py guid --machineid-info ".../msf/machineid-info"

# 离线构造 / 伪造
python3 qq_guid.py encrypt --id aabbccddeeff0011 --sn C02XXXXXXX -o machineid-info

# 指定密钥(不读本机 UUID)
python3 qq_guid.py decrypt machineid-info --key <32位hex>
python3 qq_guid.py decrypt machineid-info --uuid 0F1E2D3C-....
```

## 关于你那个空文件

`machineid-info` 是 0 字节, 说明这台机器上 QQ 还没写过它(或被清理过)。
此时 `GetMachineIDFromFile4MacOS` 返回 -1, 主流程转入 MAC 回退分支:
`machine_id = MAC + 00 00`, 再和 SN 一起算 MD5。

所以只要拿到 MAC 和 SN 就能离线复算:

```bash
python3 -c "import qq_guid as g; \
  print(g.compute_guid(bytes.fromhex('AABBCCDDEEFF')+b'\x00\x00','C02XXXXXXX').hex())"
```

## 文件清单

* `qq_tea.py` — TEA + 容器 + 字段封装(纯算法, 无第三方依赖)
* `qq_guid.py` — CLI: selftest / info / decrypt / encrypt / guid / tea
