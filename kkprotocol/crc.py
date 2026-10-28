# -*- coding: utf-8 -*-
"""常用校验算法（查表实现，纯标准库，无第三方依赖）。

- :func:`crc16_modbus` CRC-16/MODBUS，多项式 0xA001，初值 0xFFFF，无异或输出
- :func:`crc16_x25`    CRC-16/X-25（PPP/HDLC FCS-16），反射多项式 0x8408，初值 0xFFFF，输出异或 0xFFFF
- :func:`sum8` / :func:`xor8` 简单累加/异或校验
"""

from __future__ import annotations

__all__ = [
    "crc16_modbus",
    "crc16_x25",
    "crc16_ccitt",
    "crc8",
    "sum8",
    "xor8",
]


def _build_table(poly: int) -> tuple:
    table = []
    for index in range(256):
        crc = index
        for _ in range(8):
            crc = (crc >> 1) ^ poly if crc & 0x0001 else crc >> 1
        table.append(crc)
    return tuple(table)


def _build_table_msb(poly: int) -> tuple:
    """非反射（MSB-first）CRC16 查表，用于 CCITT 这类不反射的算法。"""
    table = []
    poly &= 0xFFFF
    for index in range(256):
        crc = (index << 8) & 0xFFFF
        for _ in range(8):
            crc = ((crc << 1) ^ poly) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
        table.append(crc & 0xFFFF)
    return tuple(table)


_CRC16_MODBUS_TABLE = _build_table(0xA001)
_CRC16_X25_TABLE = _build_table(0x8408)
_CRC16_CCITT_TABLE = _build_table_msb(0x1021)


def crc16_modbus(data: bytes) -> int:
    """CRC-16/MODBUS。校验向量：``crc16_modbus(b"123456789") == 0x4B37``。"""
    crc = 0xFFFF
    table = _CRC16_MODBUS_TABLE
    for byte in data:
        crc = (crc >> 8) ^ table[(crc ^ byte) & 0xFF]
    return crc


def crc16_x25(data: bytes) -> int:
    """CRC-16/X-25（PPP FCS）。校验向量：``crc16_x25(b"123456789") == 0x906E``。"""
    crc = 0xFFFF
    table = _CRC16_X25_TABLE
    for byte in data:
        crc = (crc >> 8) ^ table[(crc ^ byte) & 0xFF]
    return crc ^ 0xFFFF


def sum8(data: bytes) -> int:
    """单字节累加和（取低 8 位）。"""
    return sum(data) & 0xFF


def crc16_ccitt(data: bytes, init: int = 0x0000) -> int:
    """CRC-16/CCITT（非反射，多项式 0x1021，MSB-first）。

    两种常用初值：XModem 为 ``0x0000``，BACnet 数据段为 ``0xFFFF``。
    校验向量：``crc16_ccitt(b"123456789", 0x0000) == 0x31C3``（XModem），
    ``crc16_ccitt(b"123456789", 0xFFFF) == 0x29B1``（CCITT-FALSE）。"""
    crc = init & 0xFFFF
    table = _CRC16_CCITT_TABLE
    for byte in data:
        crc = ((crc << 8) ^ table[((crc >> 8) ^ byte) & 0xFF]) & 0xFFFF
    return crc


def crc8(data: bytes, poly: int = 0x07, init: int = 0x00) -> int:
    """通用非反射 CRC-8（MSB-first，逐位实现，无需查表）。

    BACnet MS/TP 头部校验即 ``crc8(data, poly=0x07, init=0xFF)``；
    其“发送值”为 ``(~crc8(...) & 0xFF)``，正确帧接收端复算结果为 0x55。"""
    crc = init & 0xFF
    poly &= 0xFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = ((crc << 1) ^ poly) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return crc


def xor8(data: bytes) -> int:
    """单字节异或校验。"""
    result = 0
    for byte in data:
        result ^= byte
    return result
