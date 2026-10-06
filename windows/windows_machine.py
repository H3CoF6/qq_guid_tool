#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
QQ NT (wrapper.node) Windows 端 机器码 (machine guid) 算法复现
============================================================

逆向自 Windows x64 wrapper.node (QQNT 9.9.35, imagebase 0x180000000)。
与 macOS / Linux 版都不同, 三者不要混用。

相关函数 (Windows):
    GetMachineGuid4Win            0x180CB05D2  主流程 (三级回退)
    ReadRegistry20 / DPAPI        0x180CB0B10  读文件 + CryptUnprotectData
    GetMachineGuidFromRegistry20  0x180CB1074  从 Registry2.0.db 取 G3Info_migrate
    GetRegistry20Path             0x180CB21A6  找 Registry2.0.db 路径
    SaveMachineGuid               0x180CB1562  写回 (CryptProtectData)
    GetMACFromFile                0x180CB189E  读 machine-info
    GetHDID (PhysicalDrive)       0x180CAB268
    GetCPUBrand (cpuid)           0x180CAB458
    CMACReaderEx (GetAdaptersInfo) 0x180CA8D34 / 0x180CA8E06
    MD5 init/update/final         0x180D7CCC4 / 0x180D7CCD4 / 0x180D7D5F1

主流程 (GetMachineGuid4Win):
    v4 = ReadRegistry20(...)              # 旧存储: 文件 + DPAPI
    if v4 == -1:                          # 文件不存在
        if GetMachineGuidFromRegistry20(): # 从 Registry2.0.db 取 G3Info_migrate
            SaveMachineGuid()              # 并写回
            return
        guid = MD5( 硬盘序列号 || CPU品牌 || MAC )   # 硬件回退
    elif v4 != 0:
        guid = MD5( 硬盘序列号 || CPU品牌 || MAC )
    else:
        guid = 从文件解出来的结果

硬件回退三段字符串:
    strAHardDiskID : \\\\.\\PhysicalDriveN + DeviceIoControl(0x2D1400) 取序列号
    strACPUBrand   : cpuid 0x80000002..4 拼出的 48 字节品牌串
    strAMinMac     : machine-info 文件内容; 为空时用 GetAdaptersInfo 的网卡表

混淆方式 (不是加密):
    * 字符串常量:  b ^= (i - 10)
    * 值 (G3/guid): b = ~(k ^ b), k = (len & 0xFF) ^ ((len >> 8) & 0xFF)
    * 落盘二进制:   Windows DPAPI (CryptProtectData), 绑定当前用户+机器

Registry2.0.db: 标准 SQLCipher, PRAGMA page_size=8192,
                密钥是 XOR 出来的 16 字节 "57094686228D44B0",
                数据在 platform 表 newregistry_key='G3Info_migrate'。
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import os
import struct
import subprocess
import sys

# ==========================================================================
# 从 wrapper.node 抠出来的常量
# ==========================================================================

_RAW_SQL = bytes.fromhex(
    "8592949c998fdc939b887264656a7771747e577f6b6779682e69627e7f336479"
    "77637e7668763c6a767a5244024d415254424f40595f5e54714455480f117306"
    "7f595e566556555a4c5e34246078")
_RAW_KEY = bytes.fromhex("c3c0c8c0cecdc4cbcccd384536374635")
_RAW_KEY2 = bytes.fromhex("c3c0c8c0cecdc4cbcccd384536374635")


def xor_shift(data: bytes) -> bytes:
    """b ^= (i - 10) & 0xFF  —— wrapper 字符串常量混淆"""
    return bytes((b ^ ((i - 10) & 0xFF)) for i, b in enumerate(data))


def g3_deobfuscate(data: bytes) -> bytes:
    """b = ~(k ^ b), k = (len & 0xFF) ^ ((len >> 8) & 0xFF)  —— G3/guid 值混淆"""
    n = len(data)
    k = (n & 0xFF) ^ ((n >> 8) & 0xFF)
    return bytes((~(k ^ b)) & 0xFF for b in data)


G3_SQL = xor_shift(_RAW_SQL)[:78].split(b"\x00")[0].decode("ascii")
SQLCIPHER_KEY = xor_shift(_RAW_KEY)[:16]


# ==========================================================================
# guid
# ==========================================================================

def compute_guid(harddisk_id: str, cpu_brand: str, mac: str) -> bytes:
    """硬件回退路径: guid = MD5(HDID || CPUBrand || MAC)"""
    h = hashlib.md5()
    h.update(harddisk_id.encode("utf-8"))
    h.update(cpu_brand.encode("utf-8"))
    h.update(mac.encode("utf-8"))
    return h.digest()


def guid_hex(guid: bytes, upper: bool = True) -> str:
    s = guid.hex()
    return s.upper() if upper else s


def format_mac(raw6: bytes) -> str:
    """wrapper 把 MAC 转成大写 hex, 用 '-' 连接"""
    return "-".join(f"{b:02X}" for b in raw6[:6])


IS_WINDOWS = sys.platform.startswith("win")


# ==========================================================================
# DPAPI
# ==========================================================================

def _datablob():
    import ctypes.wintypes as wt

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    return DATA_BLOB


def dpapi_unprotect(blob: bytes):
    if not IS_WINDOWS:
        return None
    DATA_BLOB = _datablob()
    crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32
    buf = ctypes.create_string_buffer(blob, len(blob))
    blobin = DATA_BLOB(len(blob), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blobout = DATA_BLOB()
    if not crypt32.CryptUnprotectData(ctypes.byref(blobin), None, None, None, None, 0,
                                      ctypes.byref(blobout)):
        return None
    try:
        return ctypes.string_at(blobout.pbData, blobout.cbData)
    finally:
        kernel32.LocalFree(blobout.pbData)


def dpapi_protect(blob: bytes):
    if not IS_WINDOWS:
        return None
    DATA_BLOB = _datablob()
    crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32
    buf = ctypes.create_string_buffer(blob, len(blob))
    blobin = DATA_BLOB(len(blob), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blobout = DATA_BLOB()
    if not crypt32.CryptProtectData(ctypes.byref(blobin), "S", None, None, None, 1,
                                    ctypes.byref(blobout)):
        return None
    try:
        return ctypes.string_at(blobout.pbData, blobout.cbData)
    finally:
        kernel32.LocalFree(blobout.pbData)


# ==========================================================================
# 三份硬件信息
# ==========================================================================

def get_harddisk_id(drive_index: int = 0):
    r"""\\\\.\\PhysicalDriveN + DeviceIoControl(0x2D1400) 取硬盘序列号。"""
    if IS_WINDOWS:
        import ctypes.wintypes as wt
        path = rf"\\.\PhysicalDrive{drive_index}"
        h = ctypes.windll.kernel32.CreateFileA(path.encode(), 0, 3, None, 3, 0, None)
        if h in (-1, 0xFFFFFFFFFFFFFFFF):
            return None
        try:
            out = ctypes.create_string_buffer(1024)
            returned = wt.DWORD(0)
            inp = ctypes.create_string_buffer(12)
            if not ctypes.windll.kernel32.DeviceIoControl(
                    h, 0x2D1400, inp, 12, out, 1024, ctypes.byref(returned), None):
                return None
            raw = out.raw
            off = 4
            while off < len(raw) and raw[off:off + 1] == b" ":
                off += 1
            return raw[off:off + 40].split(b"\x00")[0].decode("ascii", "ignore")
        finally:
            ctypes.windll.kernel32.CloseHandle(h)
    # 非 Windows: 尽力而为
    for cand in ("/sys/block/sda/device/serial", "/sys/block/nvme0n1/device/serial"):
        try:
            with open(cand) as f:
                return f.read().strip()
        except OSError:
            pass
    return None


def get_cpu_brand():
    """cpuid 0x80000002..4 的 48 字节品牌串。"""
    if IS_WINDOWS:
        try:
            out = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "(Get-CimInstance Win32_Processor).Name"],
                capture_output=True, text=True, timeout=20).stdout.strip()
            return out or None
        except Exception:
            return None
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.lower().startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return None


def get_adapters_mac() -> list[str]:
    """GetAdaptersInfo 的网卡 MAC 列表 (Windows)。"""
    if not IS_WINDOWS:
        return []
    import ctypes.wintypes as wt
    iphlpapi = ctypes.windll.iphlpapi
    size = wt.ULONG(0)
    iphlpapi.GetAdaptersInfo(None, ctypes.byref(size))
    if not size.value:
        return []
    buf = ctypes.create_string_buffer(size.value)
    if iphlpapi.GetAdaptersInfo(buf, ctypes.byref(size)) != 0:
        return []
    OFF_ADDR_LEN = 8 + 4 + 260 + 132     # Next/ComboIndex/AdapterName/Description
    OFF_ADDR = OFF_ADDR_LEN + 4
    macs, off, raw = [], 0, buf.raw
    while True:
        nxt = struct.unpack_from("<Q", raw, off)[0]
        alen = struct.unpack_from("<I", raw, off + OFF_ADDR_LEN)[0]
        if 0 < alen <= 8:
            macs.append(format_mac(raw[off + OFF_ADDR:off + OFF_ADDR + alen]))
        if nxt == 0:
            break
        off = nxt
    return macs


def get_min_mac() -> str | None:
    """strAMinMac = 所有网卡 MAC 里字符串最小 (字典序) 的那个。"""
    macs = sorted(set(get_adapters_mac()))
    return macs[0] if macs else None


# ==========================================================================
# machine-info
# ==========================================================================

def read_machine_info(path: str):
    """machine-info 内容 (明文 + 可能的 DPAPI 包一层)。"""
    if not os.path.exists(path):
        return None
    raw = open(path, "rb").read()
    if raw.lstrip()[:44].startswith(b"01 00 00 00") or raw[:4] == b"\x01\x00\x00\x00":
        dec = dpapi_unprotect(raw)
        if dec:
            return dec
    return raw


def write_machine_info(path: str, mac_str: str):
    blob = dpapi_protect(mac_str.encode("utf-8")) or mac_str.encode("utf-8")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path, "wb").write(blob)
    return blob


# ==========================================================================
# Registry2.0.db
# ==========================================================================
#
# 注意: 这是 QQ 私有格式, 不是标准 SQLCipher!
#   文件头 "SQLite header 3\0" (不是 "SQLite format 3\0")
#   前 1024 字节 = 扩展头, 之后是 XXTEA 加密的数据流
#   页大小 8192, 密钥 16 字节 "57094686228D44B0" (小端 u32 当 XXTEA key)
#   XXTEA: delta 0x9E3779B9, rounds = 0x34/n + 6, 每个 8192 页独立

REGISTRY20_EXT_HEADER = 1024
REGISTRY20_PAGE_SIZE = 8192
REGISTRY20_XXTEA_KEY = b"57094686228D44B0"


def _u32(x: int) -> int:
    return x & 0xFFFFFFFF


def xxtea_decrypt_words(v: list, key: list) -> list:
    """XXTEA 解密 (u32 列表), 与 NapCat / ntqq_tool 的实现一致。"""
    n = len(v)
    if n < 2:
        return v
    v = list(v)
    rounds = 0x34 // n + 6
    total = _u32(0x9E3779B9 * rounds)
    while total != 0:
        e = (total >> 2) & 3
        y = v[0]
        for i in range(n - 1, 0, -1):
            z = v[i - 1]
            mx = _u32(_u32(_u32(z >> 5 ^ _u32(y << 2)) + _u32(y >> 3 ^ _u32(z << 4)))
                      ^ _u32(_u32(total ^ y) + _u32(key[(i ^ e) & 3] ^ z)))
            v[i] = _u32(v[i] - mx)
            y = v[i]
        z = v[n - 1]
        mx = _u32(_u32(_u32(z >> 5 ^ _u32(y << 2)) + _u32(y >> 3 ^ _u32(z << 4)))
                  ^ _u32(_u32(total ^ y) + _u32(key[(0 ^ e) & 3] ^ z)))
        v[0] = _u32(v[0] - mx)
        total = _u32(total - 0x9E3779B9)
    return v


def xxtea_encrypt_words(v: list, key: list) -> list:
    """XXTEA 加密 (u32 列表), 用于把明文写回。"""
    n = len(v)
    if n < 2:
        return v
    v = list(v)
    rounds = 0x34 // n + 6
    total = 0
    z = v[n - 1]
    for _ in range(rounds):
        total = _u32(total + 0x9E3779B9)
        e = (total >> 2) & 3
        for i in range(n - 1):
            y = v[i + 1]
            mx = _u32(_u32(_u32(z >> 5 ^ _u32(y << 2)) + _u32(y >> 3 ^ _u32(z << 4)))
                      ^ _u32(_u32(total ^ y) + _u32(key[(i ^ e) & 3] ^ z)))
            v[i] = _u32(v[i] + mx)
            z = v[i]
        y = v[0]
        mx = _u32(_u32(_u32(z >> 5 ^ _u32(y << 2)) + _u32(y >> 3 ^ _u32(z << 4)))
                  ^ _u32(_u32(total ^ y) + _u32(key[(n - 1 ^ e) & 3] ^ z)))
        v[n - 1] = _u32(v[n - 1] + mx)
        z = v[n - 1]
    return v


def registry20_decrypt(data: bytes) -> bytes | None:
    """把 Registry2.0.db 解成标准 SQLite 文件内容。"""
    if data[:16] != b"SQLite header 3\x00":
        return None
    body = data[REGISTRY20_EXT_HEADER:]
    page = REGISTRY20_PAGE_SIZE
    if len(body) % page:
        return None
    key = list(struct.unpack("<4I", REGISTRY20_XXTEA_KEY))
    out = bytearray()
    for off in range(0, len(body), page):
        chunk = body[off:off + page]
        n = len(chunk) // 4
        words = list(struct.unpack(f"<{n}I", chunk))
        out += struct.pack(f"<{n}I", *xxtea_decrypt_words(words, key))
    if out[:15] != b"SQLite format 3":
        return None
    return bytes(out)


def registry20_encrypt(plain: bytes) -> bytes:
    """把明文 SQLite 文件内容反做成 Registry2.0.db (带扩展头)。"""
    page = REGISTRY20_PAGE_SIZE
    pad = (-len(plain)) % page
    plain = plain + b"\x00" * pad
    key = list(struct.unpack("<4I", REGISTRY20_XXTEA_KEY))
    out = bytearray()
    for off in range(0, len(plain), page):
        chunk = plain[off:off + page]
        n = len(chunk) // 4
        words = list(struct.unpack(f"<{n}I", chunk))
        out += struct.pack(f"<{n}I", *xxtea_encrypt_words(words, key))
    header = bytearray(REGISTRY20_EXT_HEADER)
    header[:16] = b"SQLite header 3\x00"
    header[16:18] = (1024).to_bytes(2, "big")
    header[18] = 0x20            # 页大小指示位, 与官方文件一致
    return bytes(header) + bytes(out)


def parse_g3_value(blob: bytes) -> bytes | None:
    """从 platform 表某个 *_migrate 的 newregistry_value 里取出 16 字节 guid。

    wrapper 的 payload 结构 (GetMachineGuidFromRegistry20 -> sub_180CFA060):
        'TD' 01 01 ver 00      # 5 字节头
        ...  u32 len @ offset 11
        obf[16] @ offset 15    # b = ~(k ^ b), k = (len & 0xFF) ^ ((len >> 8) & 0xFF)
    """
    if len(blob) < 31 or blob[:2] != b"TD":
        return None
    n = struct.unpack_from("<I", blob, 11)[0]
    if n == 0 or 15 + n > len(blob):
        return None
    obf = blob[15:15 + n]
    k = (n & 0xFF) ^ ((n >> 8) & 0xFF)
    return bytes((~(k ^ b)) & 0xFF for b in obf)


def read_guid_from_registry20_file(path: str) -> bytes | None:
    """直接从 Registry2.0.db 读 guid (无需 SQLCipher)。"""
    import sqlite3
    plain = registry20_decrypt(open(path, "rb").read())
    if plain is None:
        return None
    tmp = "/tmp/.reg20_plain.db"
    open(tmp, "wb").write(plain)
    try:
        conn = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True)
        row = conn.execute(
            "SELECT newregistry_value FROM platform WHERE newregistry_key='G3Info_migrate'"
        ).fetchone()
        conn.close()
    finally:
        pass
    if not row or row[0] is None:
        return None
    return parse_g3_value(row[0])



def registry20_paths() -> list[str]:
    """GetRegistry20Path 的四个候选路径。"""
    paths = []
    if not IS_WINDOWS:
        return paths
    shell32 = ctypes.windll.shell32
    buf = ctypes.create_string_buffer(260)
    if shell32.SHGetSpecialFolderPathA(None, buf, 0x1A, 0):      # CSIDL_APPDATA
        appdata = buf.value.decode("mbcs", "ignore")
        savepath = ""
        ini = os.path.join(appdata, "Tencent", "QQ", "UserDataInfo.ini")
        if os.path.exists(ini):
            try:
                import configparser
                cp = configparser.ConfigParser()
                cp.read(ini, encoding="utf-8")
                savepath = cp.get("UserDataSet", "UserDataSavePath", fallback="")
            except Exception:
                pass
        if savepath:
            paths.append(os.path.join(savepath, "All Users", "QQ", "Registry2.0.db"))
            paths.append(os.path.join(savepath, "All Users", "TIM", "Registry2.0.db"))
    buf2 = ctypes.create_string_buffer(260)
    if shell32.SHGetSpecialFolderPathA(None, buf2, 5, 0):        # CSIDL_PERSONAL
        docs = buf2.value.decode("mbcs", "ignore")
        paths.append(os.path.join(docs, "Tencent Files", "All Users", "QQ",
                                  "Registry2.0.db"))
        paths.append(os.path.join(docs, "Tencent Files", "All Users", "TIM",
                                  "Registry2.0.db"))
    return paths


def read_g3_from_registry20(db_path: str):
    """从 Registry2.0.db 取 G3Info_migrate -> 16 字节 guid。

    Registry2.0.db 是 QQ 私有格式 (XXTEA + 1024 扩展头), 不是 SQLCipher;
    见 registry20_decrypt / parse_g3_value。
    """
    return read_guid_from_registry20_file(db_path)


# ==========================================================================
# CLI
# ==========================================================================

def cmd_consts(args):
    print("G3 SQL        :", G3_SQL)
    print("SQLCipher key :", SQLCIPHER_KEY.decode("ascii"),
          f"(bytes {SQLCIPHER_KEY.hex()})")


def cmd_decode(args):
    data = bytes.fromhex(args.hex) if args.hex else open(args.file, "rb").read()
    print("原始 hex  :", data.hex(), f"({len(data)} 字节)")
    x = xor_shift(data)
    print("^(i-10)   :", x.hex())
    try:
        print("          :", x.split(b'\x00')[0].decode('ascii'))
    except Exception:
        pass
    print("~(k^b)    :", g3_deobfuscate(data).hex())


def cmd_guid(args):
    if args.mac is not None:
        mac = args.mac
    else:
        mi = read_machine_info(args.machine_info) if args.machine_info else None
        if mi is not None:
            mac = mi.decode("utf-8", "replace")
            print(f"[machine-info] mac = {mac!r}")
        else:
            mac = (get_min_mac() or "") if IS_WINDOWS else ""
            if mac:
                print(f"[GetAdaptersInfo] 最小 MAC = {mac!r}")
    hd = args.hd if args.hd is not None else (get_harddisk_id() or "")
    cpu = args.cpu if args.cpu is not None else (get_cpu_brand() or "")
    if not mac or not hd or not cpu:
        print("!! 缺少输入 (hd/cpu/mac), 用 --hd --cpu --mac 手动指定",
              file=sys.stderr)
    g = compute_guid(hd, cpu, mac)
    print(f"HDID  = {hd!r}")
    print(f"CPU   = {cpu!r}")
    print(f"MAC   = {mac!r}")
    print(f"guid  = {guid_hex(g)}")


def cmd_db(args):
    paths = [args.db] if args.db else registry20_paths()
    for p in paths:
        if not os.path.exists(p):
            continue
        print(f"=== {p}")
        g = read_g3_from_registry20(p)
        if g is None:
            print("    取 G3Info_migrate 失败")
        else:
            print(f"    guid = {g.hex()}")


def cmd_info(args):
    print("platform      :", "Windows" if IS_WINDOWS else sys.platform)
    print("HDID          :", get_harddisk_id())
    print("CPU brand     :", get_cpu_brand())
    if IS_WINDOWS:
        for m in get_adapters_mac():
            print("adapter MAC   :", m)
        print("min MAC       :", get_min_mac())
    for p in registry20_paths():
        print("candidate db  :", p, "存在" if os.path.exists(p) else "无")


def cmd_selftest(args):
    assert G3_SQL == 'select newregistry_value from platform where newregistry_key="G3Info_migrate";', G3_SQL
    print("[ok] G3 SQL     :", G3_SQL)
    assert SQLCIPHER_KEY == b"57094686228D44B0", SQLCIPHER_KEY
    print("[ok] SQLCipher key = 57094686228D44B0")
    mid = bytes(range(16))
    assert g3_deobfuscate(g3_deobfuscate(mid)) == mid
    print("[ok] g3 混淆自反")
    g = compute_guid("WD-WMC1T1234567", "Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz",
                     "00-1A-2B-3C-4D-5E")
    print("[ok] guid selftest =", guid_hex(g))


def main():
    p = argparse.ArgumentParser(description="QQ Windows 机器码 (guid) 工具")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("selftest", help="自检")
    sp.set_defaults(func=cmd_selftest)

    sp = sub.add_parser("consts", help="打印解出来的常量")
    sp.set_defaults(func=cmd_consts)

    sp = sub.add_parser("decode", help="对一段 hex/文件做两种反混淆")
    sp.add_argument("--hex")
    sp.add_argument("--file")
    sp.set_defaults(func=cmd_decode)

    sp = sub.add_parser("guid", help="算 guid")
    sp.add_argument("--hd")
    sp.add_argument("--cpu")
    sp.add_argument("--mac")
    sp.add_argument("--machine-info")
    sp.set_defaults(func=cmd_guid)

    sp = sub.add_parser("db", help="从 Registry2.0.db 取 G3Info_migrate")
    sp.add_argument("--db")
    sp.set_defaults(func=cmd_db)

    sp = sub.add_parser("info", help="打印本机硬件/路径")
    sp.set_defaults(func=cmd_info)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
