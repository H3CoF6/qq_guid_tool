#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
QQ (NT wrapper.node) macOS 机器码 / TEA 容器 算法复现
====================================================

逆向自 macOS x86_64 wrapper.node (QQ 7.0.2 260924):
    TEA 加密块       0x4127C1C   (16 轮, 大端密钥/数据)
    TEA 解密块       0x4127CE5
    容器加密         0x414B658
    容器解密         0x4128416
    字段读 be32      0x41502AC
    字段写 be32      0x414F682
    写字符串         0x414F9B0

容器结构 (记 E()/D() 为 TEA, 单位 8 字节块, X=明文流 C=密文):
    P_i = X_i XOR C_{i-1}              C_{-1} = 0
    C_i = E(P_i) XOR P_{i-1}           P_{-1} = 0
    X   = [head][v8 random][2 random] + payload + 00*7
    head  = (rand & 0xF8) | v8,   v8 = (-(n+10)) % 8,  n = len(payload)

字段封装: be32(len) + data  (长度字段本身也是 big-endian)
"""

from __future__ import annotations

import secrets

MASK32 = 0xFFFFFFFF
DELTA = 0x9E3779B9
BLOCK = 8


def _u32(x):
    return x & MASK32


def _key_words(key):
    if len(key) < 16:
        key = key + b"\x00" * (16 - len(key))
    return [int.from_bytes(key[4 * i:4 * i + 4], "big") for i in range(4)]


def tea_encrypt_block(block, key):
    """加密 8 字节块 -> sub_4127C1C"""
    if len(block) != 8:
        raise ValueError("TEA block must be 8 bytes")
    v0 = int.from_bytes(block[0:4], "big")
    v1 = int.from_bytes(block[4:8], "big")
    k0, k1, k2, k3 = _key_words(key)
    s = DELTA
    for _ in range(16):
        v0 = _u32(v0 + (_u32((v1 << 4) + k0) ^ _u32(v1 + s) ^ _u32((v1 >> 5) + k1)))
        v1 = _u32(v1 + (_u32((v0 << 4) + k2) ^ _u32(v0 + s) ^ _u32((v0 >> 5) + k3)))
        s = _u32(s + DELTA)
    return v0.to_bytes(4, "big") + v1.to_bytes(4, "big")


def tea_decrypt_block(block, key):
    """解密 8 字节块 -> sub_4127CE5"""
    if len(block) != 8:
        raise ValueError("TEA block must be 8 bytes")
    v0 = int.from_bytes(block[0:4], "big")
    v1 = int.from_bytes(block[4:8], "big")
    k0, k1, k2, k3 = _key_words(key)
    s = _u32(DELTA * 16)
    for _ in range(16):
        v1 = _u32(v1 - (_u32((v0 << 4) + k2) ^ _u32(v0 + s) ^ _u32((v0 >> 5) + k3)))
        v0 = _u32(v0 - (_u32((v1 << 4) + k0) ^ _u32(v1 + s) ^ _u32((v1 >> 5) + k1)))
        s = _u32(s - DELTA)
    return v0.to_bytes(4, "big") + v1.to_bytes(4, "big")


def tea_encrypt_ecb(data, key):
    if len(data) % 8:
        raise ValueError("length must be a multiple of 8")
    return b"".join(tea_encrypt_block(data[i:i + 8], key) for i in range(0, len(data), 8))


def tea_decrypt_ecb(data, key):
    if len(data) % 8:
        raise ValueError("length must be a multiple of 8")
    return b"".join(tea_decrypt_block(data[i:i + 8], key) for i in range(0, len(data), 8))


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def container_encrypt(payload, key, rng=secrets.token_bytes):
    """把 payload 打包成 QQ 加密容器 -> sub_414B658"""
    n = len(payload)
    v8 = (-(n + 10)) % 8
    head = (rng(1)[0] & 0xF8) | v8
    stream = bytes([head]) + rng(v8) + rng(2) + payload + b"\x00" * 7
    assert len(stream) % 8 == 0
    out = bytearray()
    p_prev = b"\x00" * 8
    c_prev = b"\x00" * 8
    for i in range(0, len(stream), 8):
        x_i = stream[i:i + 8]
        p_i = _xor(x_i, c_prev)
        c_i = _xor(tea_encrypt_block(p_i, key), p_prev)
        out += c_i
        p_prev, c_prev = p_i, c_i
    return bytes(out)


def container_decrypt(data, key, check_tail=True):
    """解开 QQ 加密容器 -> sub_4128416, 失败返回 None"""
    if len(data) < 16 or len(data) % 8:
        return None
    stream = bytearray()
    p_prev = b"\x00" * 8
    c_prev = b"\x00" * 8
    for i in range(0, len(data), 8):
        c_i = data[i:i + 8]
        p_i = tea_decrypt_block(c_i, key) if i == 0 else tea_decrypt_block(_xor(p_prev, c_i), key)
        stream += _xor(p_i, c_prev)
        p_prev, c_prev = p_i, c_i
    stream = bytes(stream)
    v8 = stream[0] & 0x07
    n = len(data) - v8 - 10
    if n < 0:
        return None
    start = v8 + 3
    payload = stream[start:start + n]
    tail = stream[start + n:]
    if check_tail and tail != b"\x00" * len(tail):
        return None
    return payload


def parse_fields(plain):
    """解析 be32(len)+data 序列"""
    fields, off = [], 0
    while off + 4 <= len(plain):
        ln = int.from_bytes(plain[off:off + 4], "big")
        off += 4
        if off + ln > len(plain):
            fields.append(plain[off:])
            break
        fields.append(plain[off:off + ln])
        off += ln
    return fields


def build_fields(*chunks):
    out = bytearray()
    for c in chunks:
        out += len(c).to_bytes(4, "big") + c
    return bytes(out)


def build_machineid_info(machine_id, sn):
    if len(machine_id) != 8:
        raise ValueError("machine_id must be 8 bytes")
    return build_fields(machine_id, sn.encode("utf-8"))


def parse_machineid_info(plain):
    fields = parse_fields(plain)
    mid = fields[0][:8] if fields else b""
    sn = fields[1].decode("utf-8", "replace") if len(fields) > 1 else ""
    return mid, sn
