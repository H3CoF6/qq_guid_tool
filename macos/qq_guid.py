#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
QQ (NT wrapper.node, macOS) 机器码 guid 本地计算工具
===================================================

全部逆向自 macOS x86_64 wrapper.node (QQ 7.0.2, 260924), 相关函数:
    GetMachineGuidArray        0x414D2FC  缓存入口
    GetMachineGuid4MacOS       0x414D48A  主流程
    GetMachineGuid4MacOSWithSN 0x414E158  MD5(machine_id || sn)
    GetMachineIDFromFile4MacOS 0x414DD26  读 machineid-info (TEA 解密)
    SaveMachineID2File4MacOS   0x414E6DE  写 machineid-info (TEA 加密)
    GetMACFromFile4MacOS       0x414E446  读 machine-info (明文)
    GetMacOSUUID               0x414D9BE  IOPlatformUUID
    GetSerialNumber4MacOS      0x414DB66  IOPlatformSerialNumber

核心结论
--------
    guid(16 字节) = MD5( machine_id[8 字节] || sn )

    machine_id 优先从 <data>/msf/machineid-info 里 TEA 解密读出;
    失败则回退: machine_id = 主网卡 MAC(6 字节) + 00 00

    sn 优先取 /dev/disk0 序列号, 失败回退 IOPlatformSerialNumber

    TEA 密钥 = IOPlatformUUID 字符串的前 16 个字节 (按大端解释)

文件格式
--------
    machineid-info : TEA 容器加密, 明文 = be32(8)+mid[8] + be32(len)+sn
    machine-info   : 明文       , be32(8)+ 8 字节 (MAC + 00 00)
    machine-guid   : 明文 16 字节 guid

用法
----
    python3 qq_guid.py selftest
    python3 qq_guid.py info
    python3 qq_guid.py guid
    python3 qq_guid.py decrypt <machineid-info>
    python3 qq_guid.py encrypt --id aabbccddeeff0011 --sn C02XXXX
"""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys

from qq_tea import (
    build_machineid_info,
    container_decrypt,
    container_encrypt,
    parse_fields,
    parse_machineid_info,
    tea_decrypt_block,
    tea_decrypt_ecb,
    tea_encrypt_block,
    tea_encrypt_ecb,
)


# --------------------------------------------------------------------------
# guid 计算
# --------------------------------------------------------------------------

def compute_guid(machine_id: bytes, sn: str) -> bytes:
    """guid = MD5(machine_id[8] || sn)  ->  0x414E158 / 0x414D48A"""
    h = hashlib.md5()
    h.update(machine_id[:8])
    h.update(sn.encode("utf-8"))
    return h.digest()


def key_from_uuid(uuid_str: str) -> bytes:
    """TEA 密钥 = IOPlatformUUID 前 16 字节 (不足补 0)"""
    raw = uuid_str.encode("utf-8")[:16]
    return raw + b"\x00" * (16 - len(raw))


def key_from_hex(hex_str: str) -> bytes:
    raw = bytes.fromhex(hex_str.replace(":", "").replace("-", "").replace(" ", ""))
    return (raw + b"\x00" * 16)[:16]


def guid_to_uuid_style(guid: bytes, upper: bool = True) -> str:
    s = guid.hex()
    out = f"{s[0:8]}-{s[8:12]}-{s[12:16]}-{s[16:20]}-{s[20:32]}"
    return out.upper() if upper else out


# --------------------------------------------------------------------------
# macOS 本机硬件
# --------------------------------------------------------------------------

def _ioreg_prop(class_name: str, prop: str):
    try:
        out = subprocess.run(["ioreg", "-rd1", "-c", class_name],
                             capture_output=True, text=True, timeout=10).stdout
    except Exception:
        return None
    for line in out.splitlines():
        if f'"{prop}"' in line and "=" in line:
            return line.split("=", 1)[1].strip().strip('"')
    return None


def local_uuid():
    return _ioreg_prop("IOPlatformExpertDevice", "IOPlatformUUID")


def local_serial():
    return _ioreg_prop("IOPlatformExpertDevice", "IOPlatformSerialNumber")


def local_mac_ioreg():
    """按 wrapper.node 的逻辑取主网卡 MAC (IOEthernetInterface)。"""
    try:
        out = subprocess.run(["ioreg", "-rd1", "-c", "IOEthernetInterface"],
                             capture_output=True, text=True, timeout=10).stdout
    except Exception:
        return None
    for line in out.splitlines():
        if '"IOMACAddress"' in line:
            blob = line.split("=", 1)[1]
            hx = "".join(ch for ch in blob if ch in "0123456789abcdefABCDEF")
            if len(hx) >= 12:
                return bytes.fromhex(hx[:12])
    return None


def local_disk_serial():
    """优先 /dev/disk0 的序列号 (对应 sub_414CD1C)。"""
    try:
        out = subprocess.run(["diskutil", "info", "/dev/disk0"],
                             capture_output=True, text=True, timeout=10).stdout
    except Exception:
        return None
    for line in out.splitlines():
        if "Serial Number" in line or "设备序列号" in line:
            return line.split(":", 1)[1].strip()
    return None


def local_mac():
    """Linux 风格回退: /sys/class/net 或 ifconfig。"""
    try:
        for name in ["en0", "en1", "eth0"] + os.listdir("/sys/class/net"):
            try:
                with open(f"/sys/class/net/{name}/address") as f:
                    mac = bytes.fromhex(f.read().strip().replace(":", ""))
                if len(mac) == 6 and mac != b"\x00" * 6:
                    return mac
            except Exception:
                continue
    except Exception:
        pass
    try:
        out = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=10).stdout
        for line in out.splitlines():
            if "ether" in line:
                mac = bytes.fromhex(line.split("ether")[1].split()[0].replace(":", ""))
                if mac != b"\x00" * 6:
                    return mac
    except Exception:
        pass
    return None


def _resolve_key(args) -> bytes:
    if getattr(args, "key", None):
        return key_from_hex(args.key)
    u = getattr(args, "uuid", None) or local_uuid()
    if not u:
        sys.exit("!! 需要 --uuid / --key, 且本机读不到 IOPlatformUUID")
    return key_from_uuid(u)


# --------------------------------------------------------------------------
# 子命令
# --------------------------------------------------------------------------

def cmd_selftest(args):
    key = bytes(range(16))
    blk = bytes(range(8))
    assert tea_decrypt_block(tea_encrypt_block(blk, key), key) == blk
    assert tea_decrypt_ecb(tea_encrypt_ecb(blk * 3, key), key) == blk * 3
    print("[ok] TEA 加解密往返")
    print("     E(0001020304050607, key=000102..0f) =",
          tea_encrypt_block(blk, key).hex())
    for payload in [b"", b"A", b"hello world", bytes(range(200))]:
        blob = container_encrypt(payload, key)
        assert len(blob) == len(payload) + 10 + (-(len(payload) + 10)) % 8
        assert container_decrypt(blob, key) == payload
    print("[ok] 容器加解密往返 (含空串)")
    mid = bytes.fromhex("aabbccddeeff0011")
    plain = build_machineid_info(mid, "C02TEST")
    blob = container_encrypt(plain, key)
    got = parse_machineid_info(container_decrypt(blob, key))
    assert got == (mid, "C02TEST"), got
    print("[ok] machineid-info 组装/解析")
    guid = compute_guid(mid, "C02TEST")
    print("     guid selftest =", guid.hex(), guid_to_uuid_style(guid))
    print("     guid = MD5(machine_id || sn), 与 wrapper.node 的 0x439A27C/291/AAA6 一致")


def cmd_info(args):
    print("IOPlatformUUID        :", local_uuid())
    print("IOPlatformSerialNumber :", local_serial())
    dsn = local_disk_serial()
    print("disk0 Serial Number    :", dsn)
    mac = local_mac_ioreg() or local_mac()
    print("primary MAC            :", mac.hex() if mac else None)
    u = local_uuid()
    if u:
        print("TEA key (UUID前16字节) :", key_from_uuid(u).hex())


def cmd_decrypt(args):
    key = _resolve_key(args)
    raw = open(args.file, "rb").read()
    plain = container_decrypt(raw, key, check_tail=not args.loose)
    if plain is None:
        sys.exit("!! 解密失败 (密钥不对 / 文件损坏 / 格式不符)")
    print(f"文件: {args.file}  ({len(raw)} 字节密文)")
    print(f"明文: {len(plain)} 字节")
    print(f"hex : {plain.hex()}")
    if args.out:
        open(args.out, "wb").write(plain)
        print(f"已写入 {args.out}")
    fields = parse_fields(plain)
    for i, f in enumerate(fields):
        printable = f and all(32 <= c < 127 for c in f)
        print(f"  字段{i}: len={len(f)} hex={f.hex()}"
              + (f'  ascii="{f.decode()}"' if printable else ""))
    if len(fields) >= 2 and len(fields[0]) == 8:
        mid = fields[0][:8]
        sn = fields[1].decode("utf-8", "replace")
        guid = compute_guid(mid, sn)
        print(f"\n-> machine_id = {mid.hex()}")
        print(f"-> sn         = {sn!r}")
        print(f"-> guid       = {guid.hex()}  ({guid_to_uuid_style(guid)})")


def cmd_encrypt(args):
    key = _resolve_key(args)
    mid = bytes.fromhex(args.id.replace(":", "").replace("-", ""))
    if len(mid) != 8:
        sys.exit("!! --id 必须是 8 字节 (16 个 hex 字符)")
    plain = build_machineid_info(mid, args.sn)
    blob = container_encrypt(plain, key)
    if args.out:
        open(args.out, "wb").write(blob)
        print(f"已写入 {args.out} ({len(blob)} 字节)")
    guid = compute_guid(mid, args.sn)
    print(f"machine_id : {mid.hex()}")
    print(f"sn         : {args.sn!r}")
    print(f"明文        : {plain.hex()}")
    print(f"密文        : {blob.hex()}")
    print(f"guid       : {guid.hex()}  ({guid_to_uuid_style(guid)})")


def cmd_guid(args):
    mid = None
    sn = args.sn
    if args.machineid_info:
        key = _resolve_key(args)
        plain = container_decrypt(open(args.machineid_info, "rb").read(), key)
        if plain is None:
            sys.exit("!! 解析 machineid-info 失败")
        mid, sn_file = parse_machineid_info(plain)
        sn = sn or sn_file
        print(f"machineid-info: machine_id={mid.hex()} sn={sn!r}")
    if args.id:
        mid = bytes.fromhex(args.id.replace(":", "").replace("-", ""))
    if mid is None:
        mac = local_mac_ioreg() or local_mac()
        if mac is None:
            sys.exit("!! 没有 machineid-info / --id, 也读不到 MAC")
        mid = mac + b"\x00\x00"
        print(f"[回退] MAC {mac.hex()} -> machine_id {mid.hex()}")
    if not sn:
        sn = local_serial() or ""
        print(f"[回退] IOPlatformSerialNumber: {sn!r}")
    guid = compute_guid(mid, sn)
    print(f"\nmachine_id = {mid.hex()}")
    print(f"sn         = {sn!r}")
    print(f"guid       = {guid.hex()}")
    print(f"guid(uuid) = {guid_to_uuid_style(guid)}")


def cmd_rawtea(args):
    """裸 TEA 块 (ECB) 加解密, 方便验证单块算法。"""
    key = _resolve_key(args)
    data = bytes.fromhex(args.hex)
    if len(data) % 8:
        sys.exit("!! 长度必须是 8 的倍数")
    fn = tea_encrypt_ecb if args.mode == "encrypt" else tea_decrypt_ecb
    print(fn(data, key).hex())


def main():
    p = argparse.ArgumentParser(description="QQ macOS 机器码 (guid) / TEA 容器工具")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_key(sp):
        sp.add_argument("--key", help="16 字节密钥 (hex)")
        sp.add_argument("--uuid", help="IOPlatformUUID 字符串 (默认自动读本机)")

    sp = sub.add_parser("selftest", help="自检算法")
    sp.set_defaults(func=cmd_selftest)

    sp = sub.add_parser("info", help="打印本机 UUID / SN / MAC / 密钥")
    sp.set_defaults(func=cmd_info)

    sp = sub.add_parser("decrypt", help="解密解析 machineid-info")
    sp.add_argument("file")
    sp.add_argument("-o", "--out", help="写出明文字节")
    sp.add_argument("--loose", action="store_true", help="跳过尾部校验")
    add_key(sp)
    sp.set_defaults(func=cmd_decrypt)

    sp = sub.add_parser("encrypt", help="生成 machineid-info")
    sp.add_argument("--id", required=True, help="machine_id, 8 字节 hex")
    sp.add_argument("--sn", required=True, help="序列号字符串")
    sp.add_argument("-o", "--out", help="写出密文文件")
    add_key(sp)
    sp.set_defaults(func=cmd_encrypt)

    sp = sub.add_parser("guid", help="计算 guid")
    sp.add_argument("--machineid-info", help="直接给 machineid-info 文件")
    sp.add_argument("--id", help="machine_id, 8 字节 hex")
    sp.add_argument("--sn", help="序列号")
    add_key(sp)
    sp.set_defaults(func=cmd_guid)

    sp = sub.add_parser("tea", help="裸 TEA 块 (8 字节倍数)")
    sp.add_argument("mode", choices=["encrypt", "decrypt"])
    sp.add_argument("hex")
    add_key(sp)
    sp.set_defaults(func=cmd_rawtea)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
