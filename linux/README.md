# QQ Linux 机器码 (guid) 逆向说明

逆向自 Linux x86_64 `wrapper.node`。**和 macOS 版完全不是一套**。

## 结论

```
guid(16 字节) = MD5( machine_id 字符串 || mac 字符串 )
```

* `machine_id` = `/etc/machine-id` 的原始内容(**含结尾换行**, 按 C 字符串读到第一个 NUL)
* `mac` = `<数据目录>/msf/machine-info` 文件内容做一次 **ROT13**

就这么简单, 没有 TEA, 没有密钥, 没有任何真加密。

## machine-info 为什么看起来是明文

因为 Linux 端只做了一次 **ROT13**(大小写字母各偏移 13)。文件里存的
`52-54-00-s9-07-2q` 还原后就是 `52-54-00-f9-07-2d`——恰好 ROT13 把 hex 里的
`f`/`9`/`d` 变成了 `s`/`9`/`q` 之类, 所以肉眼看像"乱码明文"。

文件格式:

```
be32(len) + ROT13("52-54-00-f9-07-2d")
```

`len` 是 ROT13 之后字符串的字节长度(17), 所以一个典型文件是 21 字节:

```
00 00 00 11  35 32 2d 35 34 2d 30 30 2d 73 39 2d 30 37 2d 32 71
```

## 选卡逻辑 (重点)

`GetMAC4Linux` (Linux 版 0x8805AB0) 的流程:

```
socket(AF_INET, SOCK_DGRAM)
ioctl(SIOCGIFCONF)      # 拿到"已配置 IPv4 地址"的网卡列表
count = ifc_len / 40    # sizeof(struct ifreq)=40
index = count - 1       # 直接取最后一台
ioctl(SIOCGIFHWADDR)    # 取它的 MAC
snprintf("%02x-%02x-%02x-%02x-%02x-%02x")
```

要点:

* **完全不筛选**:不看网卡名、不看类型、不看是否 UP、不跳过 `lo`
* **只取列表最后一台**,也就是 `SIOCGIFCONF` 返回顺序里 `index == count-1` 的那张
* 内核返回顺序 = 内核接口注册顺序(通常跟 `ip link` 的 ifindex 一致),
  所以"最后一台"经常是最后冒出来的虚拟网卡(桥接、veth、Meta 之类)
* 如果最后一台 MAC 全零(像 `Meta`、纯 `lo` 场景), 就会写出
  `00-00-00-00-00-00` —— 你本机 `nt_qq` 那个目录就是这种情况

> 换句话说: **Linux 的 machine-info 取决于"哪张网卡在 SIOCGIFCONF 里排最后"**。
> 只要机器上加了新网卡(Docker 网桥、VPN 的 Meta/tun、新增物理口),
> 最后一台就可能变, 写入的 MAC 也就跟着变 —— 这也是为什么同一台机器上
> 两个不同 QQ 数据目录会存着不同的 MAC。

## 相关函数地址 (Linux wrapper.node)

```
GetMachineGuidArray     0x8804C60    缓存入口, 全局 qword_9127258
GetMachineGuid4Linux    0x8804DF0    主流程
GetLinuxMachineID       0x88055E0    读 /etc/machine-id
GetMAC4Linux            0x8805AB0    枚举网卡取最后一台
GetMACFromFile          0x8805720    读 machine-info
SaveMachineInfo         0x8805D00    写 machine-info
序列化器 init/attach/dump 0x88075D0 / 0x8808470 / 0x8807700
be32 读/写               0x8808C00 / 0x8807AD0
MD5 init/update/final   0x8AE17E0 / 0x8AE1800 / 0x8AE2040
```

## 用法

```bash
python3 linux_machine.py selftest
python3 linux_machine.py info
python3 linux_machine.py decode --guid
python3 linux_machine.py guid --machine-info ~/.config/QQ/nt_qq/global/nt_data/msf/machine-info
python3 linux_machine.py encode --mac 52:54:00:f9:07:2d -o machine-info
```

## 关于结尾换行

`/etc/machine-id` 文件本身是 **33 字节**(32 hex + `\n`)。wrapper.node 用
C 字符串方式读(到 NUL 为止), 换行 **保留** 在字符串里参与 MD5。
工具默认保留换行; 若某天对不上, 用 `--strip-newline` 试试去换行的版本。
