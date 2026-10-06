# QQ Windows 机器码 (guid) 逆向说明

逆向自 Windows x64 `wrapper.node`(QQNT 9.9.35, imagebase `0x180000000`)。
**和 macOS / Linux 版完全不同**, 三者别混用。

## 结论

```
guid(16 字节) = MD5( 硬盘序列号 || CPU品牌串 || MAC字符串 )
```

这是"硬件回退"路径。优先级更高的路径是从本地数据库/文件里直接取 guid:

```
ReadRegistry20(文件 + DPAPI)
  ├─ 命中  -> 用解出来的 guid
  ├─ 文件不存在 -> GetMachineGuidFromRegistry20 (读 Registry2.0.db)
  │                 ├─ 命中 -> SaveMachineGuid 写回, 返回
  │                 └─ 失败 -> 走硬件回退
  └─ 其它   -> 走硬件回退
```

三段字符串的来源:

* **strAHardDiskID** — `\\.\PhysicalDrive0` + `DeviceIoControl(0x2D1400)`
  取硬盘序列号(ASCII)
* **strACPUBrand** — `cpuid 0x80000002..0x80000004`, 48 字节品牌串
  (如 `Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz`)
* **strAMinMac** — 优先读 `<data>/msf/machine-info` 的内容;
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
%APPDATA%\Tencent\QQ\UserDataInfo.ini
    [UserDataSet] UserDataSavePath=<X>
    -> <X>\All Users\QQ\Registry2.0.db
    -> <X>\All Users\TIM\Registry2.0.db
%USERPROFILE%\Documents\Tencent Files\All Users\QQ\Registry2.0.db
%USERPROFILE%\Documents\Tencent Files\All Users\TIM\Registry2.0.db
```

你 `~/Downloads/All Users.zip` 里的 `All Users/QQ/Registry2.0.db` 就是第一个
路径下的那份, 正是 `GetMachineGuidFromRegistry20` 要读的文件。

## 相关函数地址

```
GetMachineGuid4Win            0x180CB05D2   主流程
ReadRegistry20 / DPAPI        0x180CB0B10
GetMachineGuidFromRegistry20  0x180CB1074
GetRegistry20Path             0x180CB21A6
SaveMachineGuid               0x180CB1562
GetMACFromFile                0x180CB189E
GetHDID (PhysicalDrive)       0x180CAB268
GetCPUBrand (cpuid)           0x180CAB458
CMACReaderEx / GetAdaptersInfo 0x180CA8D34 / 0x180CA8E06
MD5 init/update/final         0x180D7CCC4 / 0x180D7CCD4 / 0x180D7D5F1
```

## 用法

```bash
python3 windows_machine.py selftest     # 自检 (常量 + 混淆自反)
python3 windows_machine.py consts       # 打印解出来的 SQL / 密钥
python3 windows_machine.py info         # 本机 HDID / CPU / 网卡 MAC / 候选路径
python3 windows_machine.py guid         # 自动取三段算 guid
python3 windows_machine.py guid --hd WD-XXX --cpu "Intel..." --mac 00-1A-2B-3C-4D-5E
python3 windows_machine.py decode --hex 8592949c...   # 反混淆任意数据
python3 windows_machine.py db --db "All Users/QQ/Registry2.0.db"
```

`guid` / `info` / `db` 的硬件与 DPAPI 部分需要在 Windows 上跑;
`selftest` / `consts` / `decode` 在任何平台都能跑。
