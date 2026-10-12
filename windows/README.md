# QQ Windows 机器码 (guid) 逆向说明

逆向自 Windows x64 `wrapper.node`(QQNT 9.9.35, imagebase `0x180000000`)。
**和 macOS / Linux 版完全不同**, 三者别混用。

## 结论

```
guid(16 字节) = MD5( 硬盘序列号 || CPU品牌串 || MAC字符串 )
```

这是"硬件回退"路径。优先级更高的路径是从本地文件/数据库里直接取 guid:

```
ReadRegistry20(<msf>\Registry20, 文件 + DPAPI)       ← 第 1 优先
  ├─ 命中        -> 用解出来的 guid
  ├─ 文件不存在  -> GetMachineGuidFromRegistry20 (读 Registry2.0.db)
  │                  ├─ 命中 -> SaveMachineGuid 写回, 返回
  │                  └─ 失败 -> 走硬件回退
  └─ 文件在但解不开(-2) -> 直接走硬件回退
```

优先级从高到低（`GetMachineGuid4Win` 里的真实分支顺序）:

| # | 来源 | 位置 | 加密 |
|---|------|------|------|
| 1 | `<msf>\Registry20` | `…\nt_qq\global\nt_data\msf\Registry20` | DPAPI |
| 2 | `All Users\{QQ,TIM}\Registry2.0.db` | `<Tencent Files>\All Users\...` | XXTEA 页流 |
| 3 | 硬件回退 | 本机硬件现算 | 无 |

> **全新装机的 NT QQ 通常既没有 `All Users\` 目录、也没有 `Registry2.0.db`**
>（它们都是旧版 QQ 的遗留物）。这种机器上 QQ 走的就是第 1 或第 3 条路。

三段字符串的来源:

* **strAHardDiskID** — `\\.\PhysicalDrive0` + `DeviceIoControl(0x2D1400)`
  取硬盘序列号(ASCII)
* **strACPUBrand** — `cpuid 0x80000002..0x80000004`, 48 字节品牌串
  (如 `Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz`)
* **strAMinMac** — 优先读 `<msf>\machine-info` 的内容（存 MAC 字符串，**明文**）;
  为空则用 `GetAdaptersInfo` 枚举网卡, 取**字符串最小**的那个 MAC

## 混淆方式 (不是加密)

三个混淆层次, 从外到内:

1. **DPAPI** — 二进制落盘时 `CryptProtectData` / `CryptUnprotectData`,
   绑定当前 Windows 用户 + 机器, 换机器就解不开
2. **值混淆** — `b = ~(k ^ b)`, `k = (len & 0xFF) ^ ((len >> 8) & 0xFF)`
3. **字符串常量混淆** — `b ^= (i - 10) & 0xFF`

反混淆后能直接看到明文 SQL, 例如:

```
select newregistry_value from platform where newregistry_key="G3Info_migrate";
```

`G3Info_migrate` 就是存 guid 的地方(16 字节, 上面第 2 层的值混淆)。

## Registry2.0.db

**不是 SQLCipher**, 是 QQ 私有格式: **1024 字节扩展头 + XXTEA 加密的页流**。

```
文件头:  "SQLite header 3\0"   (注意不是标准的 "SQLite format 3\0")
偏移 16: 04 00  (page size 字段, 1024)
偏移 18: 20
偏移 1024 起: XXTEA 加密的数据流, 每 8192 字节一页, 逐页独立加解密
```

XXTEA 参数:

```
key    = b"57094686228D44B0"  (16 字节, 拆成 4 个小端 u32 当 key[0..3])
delta  = 0x9E3779B9
rounds = 0x34 // n + 6        (n = 每页的 u32 个数 = 8192/4 = 2048, 故 rounds=6)
```

解密后就是标准 SQLite: 数据表 `platform`, 键 `newregistry_key='G3Info_migrate'`,
其 `newregistry_value` 里存着 guid。

`G3Info_migrate` 的 value 是一个 TLV:

```
'TD' 01 01 ver 00            # 5 字节头
...  u32 len @ offset 11     # guid 长度, = 16
obf[16] @ offset 15          # guid 混淆: b = ~(k ^ b)
k = (len & 0xFF) ^ ((len >> 8) & 0xFF)   # len=16 -> k=0x10
```

本工具已实现完整链路: `registry20_decrypt` → `sqlite3` → `parse_g3_value`,
并且 `registry20_encrypt` 能逐字节还原原文件(已用真实样本验证)。

> 之前用标准 sqlcipher 打不开就是因为方向错了 —— 它压根不是 SQLCipher。

## 路径 (GetRegistry20Path)

```
C:\Users\Public\Documents\Tencent\QQ\UserDataInfo.ini      ← CSIDL_COMMON_DOCUMENTS (0x2E)
    [UserDataSet] UserDataSavePath=<X>
    -> <X>\All Users\QQ\Registry2.0.db
    -> <X>\All Users\TIM\Registry2.0.db
%USERPROFILE%\Documents\Tencent Files\All Users\QQ\Registry2.0.db    ← CSIDL_PERSONAL (5)
%USERPROFILE%\Documents\Tencent Files\All Users\TIM\Registry2.0.db
```

> ini 是从 **`C:\Users\Public\Documents\Tencent\QQ\UserDataInfo.ini`** 读的
> （`SHGetSpecialFolderPathA(CSIDL_COMMON_DOCUMENTS)`），**不是 `%APPDATA%`**。
> 早期版本这里写成 `0x1A`(CSIDL_APPDATA) 是错的。这点和 weq 的
> `dirname(home)/Public/Documents/...` 一致。

你 `~/Downloads/All Users.zip` 里的 `All Users/QQ/Registry2.0.db` 就是第一个
路径下的那份, 正是 `GetMachineGuidFromRegistry20` 要读的文件。

## `<msf>\Registry20`（第 1 优先，DPAPI）

与上面那条**完全不同的文件**，别再混：`Registry20` 存的是 16 字节 guid，
`machine-info` 存的是 MAC 字符串。两者同在 `msf` 目录下，而 `msf` 与
`Emoji` / `Log` / `Login` 同级（`nt_data` 内）:

```
<Tencent Files>\nt_qq\global\nt_data\msf\Registry20     ← guid 缓存 (DPAPI)
<Tencent Files>\nt_qq\global\nt_data\msf\machine-info   ← MAC 缓存 (明文)
```

`Registry20` = `CryptProtectData(plain, descr="S", entropy=NULL, flags=1)`
生成的标准 DPAPI blob（provider `df9d8cd0-1501-11d1-8c7a-00c04fc297eb`）:

```
plain = [BE u32 总长][16 字节 guid]     # 总长含自身那 4 字节, 故 = 20
guid[i] = ~(k ^ obf[i])                 # k = 0x10, 与 G3Info_migrate 同款
```

**entropy 为 NULL**，所以在生成该文件的同一 Windows 账户下（`CurrentUser`
作用域）直接 `CryptUnprotectData(blob, None, ...)` 就能解开；换用户/换机器
（需要 masterkey，依赖账户密码与 SID）则解不开。

已验证样本（`~/Downloads/Registry20`）:

```
sha256  7b9bb41d45f661c1717e0e7556da9b300bdf7f585d34bcd6fe2226b98e2169ce
plain   00000014 54e9c3ad6ff42066cc2a168a3d934a47
guid    bb062c42801bcf8923c5f965d27ca5a8
```

## 相关函数地址

```
GetMachineGuid4Win            0x180CB05D2   主流程
ReadRegistry20 / DPAPI        0x180CB0B10   读 <msf>\Registry20 (返回 0/-1/-2)
GetMachineGuidFromRegistry20  0x180CB1074
GetRegistry20Path             0x180CB21A6
SaveMachineGuid               0x180CB1562
GetMACFromFile                0x180CB189E   读 <msf>\machine-info
GetHDID (PhysicalDrive)       0x180CAB268
GetCPUBrand (cpuid)           0x180CAB458
CMACReaderEx / GetAdaptersInfo 0x180CA8D34 / 0x180CA8E06
MD5 init/update/final         0x180D7CCC4 / 0x180D7CCD4 / 0x180D7D5F1
```

`ReadRegistry20` 的返回值是三态的（`GetMachineGuid4Win` 据此分支）:

| ret | 含义 |
|-----|------|
| `0`  | `<msf>\Registry20` 存在且 DPAPI 解密成功 |
| `-1` | 文件不存在 → 继续试 `Registry2.0.db`，失败再硬件回退 |
| `-2` | 文件在但解密失败 → **跳过** `Registry2.0.db`，直接硬件回退 |

## 用法

```bash
python3 windows_machine.py selftest     # 自检 (常量 + 混淆自反)
python3 windows_machine.py consts       # 打印解出来的 SQL / 密钥
python3 windows_machine.py info         # 本机 HDID / CPU / 网卡 MAC / 候选路径
python3 windows_machine.py msf --data-root "D:\Tencent\Tencent Files"
                                        # 只走 <msf>\Registry20 (DPAPI)
python3 windows_machine.py compare --data-root "D:\Tencent\Tencent Files"
                                        # ★ 三路对照: msf / Registry2.0.db / 硬件回退
python3 windows_machine.py guid         # 自动取三段算 guid
python3 windows_machine.py guid --hd WD-XXX --cpu "Intel..." --mac 00-1A-2B-3C-4D-5E
python3 windows_machine.py decode --hex 8592949c...   # 反混淆任意数据
python3 windows_machine.py db --db "All Users/QQ/Registry2.0.db"
python3 windows_machine.py msf --path "D:\...\msf\Registry20"
```

`compare` 会把三路各自的 guid 都打出来并判定是否一致（一致退出码 0，
不一致 2，全都没拿到 1）。**推荐在目标机器上先跑这个**，一眼就能看出
该机到底走的是哪条路、以及三方是否互证。

`guid` / `info` / `db` / `msf` / `compare` 的硬件与 DPAPI 部分需要在
Windows 上跑；`selftest` / `consts` / `decode` 在任何平台都能跑。

> `compare --data-root` 只认 `<root>\nt_qq\global\nt_data\msf` 这类布局；
> 若你的机器布局不同，用 `--path` 直接指到 `Registry20` 文件更稳。
