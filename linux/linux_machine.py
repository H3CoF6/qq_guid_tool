#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
QQ NT (wrapper.node) Linux 端 机器码 (machine guid) 算法复现
==========================================================

逆向自 Linux x86_64 wrapper.node。与 macOS 版完全不同, 别混用。

相关函数 (Linux):
    GetMachineGuidArray    0x8804C60   缓存入口
    GetMachineGuid4Linux   0x8804DF0   主流程 -> guid = MD5(machine-id || mac)
    GetLinuxMachineID      0x88055E0   读 /etc/machine-id
    GetMAC4Linux           0x8805AB0   枚举网卡, 取最后一个
    GetMACFromFile         0x8805720   读 <data>/msf/machine-info (ROT13)
    SaveMachineInfo        0x8805D00   写 <data>/msf/machine-info (ROT13)

核心结论
--------
    guid(16 字节) = MD5( machine_id 字符串 || mac 字符串 )

    machine_id = /etc/machine-id 的原始内容(含结尾换行, 按 C 字符串截断到 NUL)
    mac        = machine-info 文件内容做一次 ROT13

    machine-info 文件格式 (明文, 无任何加密):
        be32(len) + ROT13(mac_string)
        mac_string 形如 "52-54-00-f9-07-2d" (6 组两位小写 hex, 连字符分隔)

    所以 machine-info 看起来像明文, 因为它只是 ROT13 混淆, 不是加密。

选卡逻辑 (GetMAC4Linux / 0x8805AB0)
-----------------------------------
    socket(AF_INET, SOCK_DGRAM)
    ioctl(SIOCGIFCONF) -> 得到已配置 IPv4 地址的网卡列表 (ifreq, stride 40)
    count = ifc_len / 40
    取 index = count - 1 的那张网卡 (列表最后一台!)
    ioctl(SIOCGIFHWADDR) 取该网卡 MAC
    格式化为 "%02x-%02x-%02x-%02x-%02x-%02x"

    注意: 不按名字/类型/UP 状态筛选, 不跳过 lo, 就取最后一台。
    如果最后一台 MAC 全零 (例如某些虚拟口), 就得到 "00-00-00-00-00-00"。
"""

from __future__ import annotations

import argparse
import ctypes
import fcntl
import hashlib
import os
import socket
import struct
import sys

SIOCGIFCONF = 0x8912
SIOCGIFHWADDR = 0x8927
IFREQ_SIZE = 40          # sizeof(struct ifreq) on Linux x86_64


# --------------------------------------------------------------------------
# machine-info 文件 (be32 长度 + ROT13)
# --------------------------------------------------------------------------

def rot13_bytes(data: bytes) -> bytes:
    """只对 ASCII 字母做 ROT13, 其它字节原样保留。"""
    out = bytearray(data)
    for i, c in enumerate(out):
        if 0x41 <= c <= 0x5A:
            out[i] = (c - 0x41 + 13) % 26 + 0x41
        elif 0x61 <= c <= 0x7A:
            out[i] = (c - 0x61 + 13) % 26 + 0x61
    return bytes(out)


def mac_bytes_to_string(mac: bytes) -> str:
    """6 字节 MAC -> "52-54-00-f9-07-2d" (连字符, 小写)。"""
    return "-".join(f"{b:02x}" for b in mac[:6])


def build_machine_info(mac: bytes) -> bytes:
    """构造 machine-info 文件内容: be32(len) + ROT13(mac_string)。"""
    s = rot13_bytes(mac_bytes_to_string(mac).encode("ascii"))
    return struct.pack(">I", len(s)) + s


def parse_machine_info(data: bytes) -> str:
    """解析 machine-info, 返回 ROT13 还原后的 mac 字符串; 失败抛异常。"""
    if len(data) < 4:
        raise ValueError("太短")
    ln = struct.unpack(">I", data[:4])[0]
    body = data[4:4 + ln]
    if ln == 0 or len(body) != ln:
        raise ValueError(f"长度字段 {ln} 与文件不符 (共 {len(data)} 字节)")
    return rot13_bytes(body).decode("ascii", "replace")


# --------------------------------------------------------------------------
# /etc/machine-id
# --------------------------------------------------------------------------

def read_machine_id(path: str = "/etc/machine-id", keep_newline: bool = True) -> bytes:
    """按 wrapper.node 的做法读 /etc/machine-id (C 字符串语义, 到第一个 NUL 为止)。"""
    with open(path, "rb") as f:
        raw = f.read(127)
    nul = raw.find(b"\x00")
    if nul >= 0:
        raw = raw[:nul]
    if not keep_newline:
        raw = raw.rstrip(b"\r\n")
    return raw


# --------------------------------------------------------------------------
# GetMAC4Linux —— 枚举网卡, 取最后一台
# --------------------------------------------------------------------------

class _Ifconf(ctypes.Structure):
    _fields_ = [("ifc_len", ctypes.c_int), ("ifc_buf", ctypes.c_void_p)]


class _IfreqHw(ctypes.Structure):
    _fields_ = [("ifr_name", ctypes.c_char * 16), ("ifr_data", ctypes.c_ubyte * 24)]


def list_ipv4_interfaces():
    """返回 SIOCGIFCONF 给出的网卡名列表 (顺序与内核返回一致, stride 40)。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        buf = ctypes.create_string_buffer(640)
        ic = _Ifconf(640, ctypes.cast(buf, ctypes.c_void_p))
        fcntl.ioctl(s.fileno(), SIOCGIFCONF, ic)
        raw = buf.raw[:ic.ifc_len]
        names = []
        for i in range(len(raw) // IFREQ_SIZE):
            ent = raw[i * IFREQ_SIZE:(i + 1) * IFREQ_SIZE]
            names.append(ent[:16].split(b"\x00")[0].decode("ascii", "replace"))
        return names
    finally:
        s.close()


def iface_mac(name: str) -> bytes | None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        r = _IfreqHw()
        r.ifr_name = name.encode()
        fcntl.ioctl(s.fileno(), SIOCGIFHWADDR, r)
        return bytes(r.ifr_data[2:8])
    except OSError:
        return None
    finally:
        s.close()


def get_mac4linux() -> tuple[str | None, bytes | None, list]:
    """
    GetMAC4Linux 的 Python 复现。
    返回 (选中的网卡名, MAC 6 字节, 全部网卡[(name, mac)])。
    """
    names = list_ipv4_interfaces()
    if not names:
        return None, None, []
    all_ifaces = [(n, iface_mac(n)) for n in names]
    last = names[-1]
    return last, iface_mac(last), all_ifaces


def get_mac4linux_string() -> str | None:
    name, mac, _ = get_mac4linux()
    if mac is None:
        return None
    return mac_bytes_to_string(mac)


# --------------------------------------------------------------------------
# guid
# --------------------------------------------------------------------------

def compute_guid(machine_id: bytes, mac_string: str) -> bytes:
    """guid = MD5(machine_id 字符串 || mac 字符串)  ->  sub_8804DF0"""
    h = hashlib.md5()
    h.update(machine_id)
    h.update(mac_string.encode("utf-8"))
    return h.digest()


def compute_guid_from_files(machine_info_path: str,
                            machine_id_path: str = "/etc/machine-id",
                            keep_newline: bool = True):
    """从 machine-info 文件和 /etc/machine-id 直接算出 guid。"""
    mid = read_machine_id(machine_id_path, keep_newline=keep_newline)
    mac = parse_machine_info(open(machine_info_path, "rb").read())
    return compute_guid(mid, mac), mid, mac


def guid_hex(guid: bytes, upper: bool = True) -> str:
    s = guid.hex()
    return s.upper() if upper else s


DEFAULT_MACHINE_INFO = [
    os.path.expanduser("~/.config/QQ/nt_qq/global/nt_data/msf/machine-info"),
    os.path.expanduser("~/.config/QQ/global/nt_data/msf/machine-info"),
]


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def cmd_selftest(args):
    for mac in [bytes.fromhex("525400f9072d"), bytes(6), bytes(range(6))]:
        blob = build_machine_info(mac)
        assert parse_machine_info(blob) == mac_bytes_to_string(mac)
    print("[ok] machine-info 组装/解析 (be32 + ROT13) 往返")
    assert rot13_bytes(rot13_bytes(b"52-54-00-f9-07-2d")) == b"52-54-00-f9-07-2d"
    print("[ok] ROT13 自反")
    g = compute_guid(b"abc", "52-54-00-f9-07-2d")
    print("     guid(abc|52-54-00-f9-07-2d) =", guid_hex(g))
    print("     guid = MD5(machine-id || mac), 对应 sub_8804DF0")


def cmd_info(args):
    mid_raw = read_machine_id()
    print("machine-id 文件原文 :", repr(mid_raw))
    names = list_ipv4_interfaces()
    print(f"SIOCGIFCONF 网卡顺序 (共 {len(names)} 台):")
    for i, n in enumerate(names):
        mac = iface_mac(n)
        tag = "  <== 选中(最后一台)" if i == len(names) - 1 else ""
        print(f"  [{i}] {n:20s} {mac_bytes_to_string(mac) if mac else '?':18s}{tag}")
    name, mac, _ = get_mac4linux()
    print(f"\nGetMAC4Linux 选中: {name}  MAC={mac_bytes_to_string(mac) if mac else None}")
    print(f"mac 字符串       : {get_mac4linux_string()!r}")
    g = compute_guid(mid_raw, get_mac4linux_string() or "")
    print(f"guid(machine-id|mac) = {guid_hex(g)}")
    for p in DEFAULT_MACHINE_INFO:
        if os.path.exists(p):
            print(f"\n现有文件 {p}:")
            d = open(p, "rb").read()
            print("  原始:", d.hex())
            try:
                print("  解析: mac =", repr(parse_machine_info(d)))
            except Exception as e:
                print("  解析失败:", e)


def cmd_decode(args):
    data = open(args.file, "rb").read()
    print(f"文件: {args.file} ({len(data)} 字节)")
    print("原始 hex:", data.hex())
    print("原始 str:", repr(data))
    print("解析 mac :", repr(parse_machine_info(data)))
    if args.guid:
        keep = not args.strip_newline
        g, mid, mac = compute_guid_from_files(args.file, keep_newline=keep)
        print(f"machine-id : {mid!r}")
        print(f"guid       : {guid_hex(g)}")


def cmd_guid(args):
    if args.machine_info:
        g, mid, mac = compute_guid_from_files(args.machine_info,
                                              keep_newline=not args.strip_newline)
        print(f"machine-id : {mid!r}")
        print(f"mac        : {mac!r}")
        print(f"guid       : {guid_hex(g)}")
        return
    mid = read_machine_id(keep_newline=not args.strip_newline)
    mac = args.mac or get_mac4linux_string()
    if not mac:
        sys.exit("!! 无法获得 mac (可用 --mac 指定)")
    g = compute_guid(mid, mac)
    print(f"machine-id : {mid!r}")
    print(f"mac        : {mac!r}")
    print(f"guid       : {guid_hex(g)}")


def cmd_encode(args):
    mac = bytes.fromhex(args.mac.replace(":", "").replace("-", ""))
    if len(mac) != 6:
        sys.exit("!! --mac 必须是 6 字节")
    blob = build_machine_info(mac)
    print(f"mac 字符串 : {mac_bytes_to_string(mac)!r}")
    print(f"ROT13      : {rot13_bytes(mac_bytes_to_string(mac).encode())!r}")
    print(f"文件 hex   : {blob.hex()}")
    if args.out:
        open(args.out, "wb").write(blob)
        print(f"已写入 {args.out}")
    mid = read_machine_id(keep_newline=not args.strip_newline)
    print(f"guid       : {guid_hex(compute_guid(mid, mac_bytes_to_string(mac)))}")


def main():
    p = argparse.ArgumentParser(description="QQ Linux 机器码 (guid) 工具")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("selftest", help="自检")
    sp.set_defaults(func=cmd_selftest)

    sp = sub.add_parser("info", help="打印 /etc/machine-id + 网卡列表 + 选卡 + guid")
    sp.set_defaults(func=cmd_info)

    sp = sub.add_parser("decode", help="解析 machine-info 文件")
    sp.add_argument("file", nargs="?", default=None)
    sp.add_argument("--guid", action="store_true", help="顺带算 guid")
    sp.add_argument("--strip-newline", action="store_true",
                    help="machine-id 去掉结尾换行 (默认保留)")
    sp.set_defaults(func=cmd_decode)

    sp = sub.add_parser("guid", help="算 guid")
    sp.add_argument("--machine-info", help="machine-info 文件路径")
    sp.add_argument("--mac", help="直接指定 mac 字符串")
    sp.add_argument("--strip-newline", action="store_true")
    sp.set_defaults(func=cmd_guid)

    sp = sub.add_parser("encode", help="生成 machine-info")
    sp.add_argument("--mac", required=True, help="6 字节 MAC")
    sp.add_argument("-o", "--out")
    sp.add_argument("--strip-newline", action="store_true")
    sp.set_defaults(func=cmd_encode)

    args = p.parse_args()
    if args.cmd == "decode" and not args.file:
        for p_ in DEFAULT_MACHINE_INFO:
            if os.path.exists(p_):
                args.file = p_
                break
    args.func(args)


if __name__ == "__main__":
    main()
