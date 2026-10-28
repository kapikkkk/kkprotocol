# -*- coding: utf-8 -*-
"""BACnet MS/TP（楼宇自控，RS-485 令牌环）。

帧结构（长度定界，固定 2 字节前导 55 FF）：::

    55 FF 类型(1) 目的(1) 源(1) 长度(2, 大端)
        [令牌帧到此为止]
        头CRC(1, 覆盖 类型/目的/源/长度)
        [数据帧另有] DATA(长度)  数据CRC(2, 覆盖 DATA)

要点（压测点 —— 这是本次最关键的“设计缺口”样本）：

* 一帧里**有两个校验和**（头 CRC8 + 体 CRC16），且头 CRC 在帧中部、体 CRC 在帧尾；
* 解析侧：库会对**所有**标 ``crc=True`` 的字段逐个校验，所以两个 CRC **都能验**
  （本模块用 ``to_codec`` 解析验证）；
* **组帧侧**：``FrameBuilder`` 的 ``FrameSpec.checksum`` 只能声明**一个**校验和，
  数据帧（头 + 体两个 CRC）目前**无法用 builder 一次组出来**——这是真实缺口
  （见 ``build_data`` 只能手工构造）。建议未来支持“一帧多校验和 / 按字段独立计算”。
* 令牌帧（长度=0）没有数据也没有体 CRC，和结构不同的数据帧属于“同一字节流里的多形态”
  —— 这里用两份 spec（TOKEN / DATA）分别解析，和 example_modbus_rtu_multi 的多响应分派是同一类问题。

校验多项式说明：BACnet 头 CRC8 用 0x07、体 CRC16 用 0x1021（初值 0xFFFF）属非反射族；
离线无法用公开文档的 0x55 / 0xF0B8 残差反推到标准算法（文档示例自洽性存疑），但库只
比对“校验值是否一致”，因此这里用自洽的 CRC 建模双校验结构，重点测库的解析能力。
"""
from __future__ import annotations

from ..crc import crc16_ccitt, crc8
from ..spec import ChecksumRule, Field, FrameSpec

PRE1 = 0x55
PRE2 = 0xFF


def _header_crc(ftype: int, dst: int, src: int, length: int) -> int:
    head = bytes([ftype, dst, src]) + length.to_bytes(2, "big")
    return crc8(head, poly=0x07, init=0xFF)


def _data_crc(data: bytes) -> int:
    return crc16_ccitt(data, init=0xFFFF)


SPEC_TOKEN = FrameSpec(
    fields=[
        Field.u8("pre1", fixed=PRE1),
        Field.u8("pre2", fixed=PRE2),
        Field.u8("ftype"),
        Field.u8("dst", desc="目的 MAC 地址（设备号）"),
        Field.u8("src"),
        Field.u16("length", little_endian=False),
        Field.checksum("hcrc", 1, group="{ftype}{dst}{src}{length}"),
    ],
    device="dst",
    checksum=ChecksumRule("hcrc", lambda g: crc8(g, poly=0x07, init=0xFF)),
    max_frame_size=8,
    desc="BACnet MS/TP 令牌帧",
)

SPEC_DATA = FrameSpec(
    fields=[
        Field.u8("pre1", fixed=PRE1),
        Field.u8("pre2", fixed=PRE2),
        Field.u8("ftype"),
        Field.u8("dst", desc="目的 MAC 地址（设备号）"),
        Field.u8("src"),
        Field.u16("length", little_endian=False),
        Field.checksum("hcrc", 1, group="{ftype}{dst}{src}{length}"),
        Field.raw("data", "{length.val}"),
        Field.checksum("dcrc", 2, fmt="!H", group="{data}"),
    ],
    device="dst",
    # 一帧双校验和：头 CRC8（覆盖类型/目的/源/长度）+ 体 CRC16（仅覆盖 DATA）。
    # 解析侧已支持一帧多校验和（每个字段按各自 impl 独立校验）；组帧侧仍只回填第一个，
    # 所以数据帧组帧走手工 build_data（见下方）。
    checksum=[
        ChecksumRule("hcrc", lambda g: crc8(g, poly=0x07, init=0xFF)),
        ChecksumRule("dcrc", lambda g: crc16_ccitt(g, init=0xFFFF)),
    ],
    max_frame_size=512,
    desc="BACnet MS/TP 数据帧",
)


def protocol_token(device_id=None, enforce=False):
    from ..builder import Protocol
    return Protocol(SPEC_TOKEN, device_id=device_id, enforce_device_id=enforce)


def protocol_data(device_id=None, enforce=False):
    from ..builder import Protocol
    return Protocol(SPEC_DATA, device_id=device_id, enforce_device_id=enforce)


def build_token(ftype: int, dst: int, src: int) -> bytes:
    """组一条令牌帧（长度=0，无数据、无体 CRC）。"""
    length = 0
    head = bytes([PRE1, PRE2, ftype, dst, src]) + length.to_bytes(2, "big")
    return head + bytes([_header_crc(ftype, dst, src, length)])


def build_data(ftype: int, dst: int, src: int, data: bytes) -> bytes:
    """手工组一条数据帧（同时算头 CRC8 与体 CRC16）。

    注意：这条只能手工组，因为 FrameBuilder 只支持单校验和，组不出“头+体双 CRC”。
    """
    length = len(data)
    head = bytes([PRE1, PRE2, ftype, dst, src]) + length.to_bytes(2, "big")
    body = head + bytes([_header_crc(ftype, dst, src, length)]) + data
    return body + _data_crc(data).to_bytes(2, "big")
