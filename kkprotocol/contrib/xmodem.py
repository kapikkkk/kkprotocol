# -*- coding: utf-8 -*-
"""XModem / YModem 文件传输协议（串口，块传输）。

XModem 帧结构（长度定界，固定 133 字节，无帧头定界符，靠同步字节 0x01 找起点）：::

    SOH(0x01)  块号(1)  ~块号(1)  DATA(128)  CRC16-CCITT(2)

YModem 把 DATA 扩到 1024 字节、标志改成 STX(0x02)，其余相同。

要点（压测点）：

* **帧大小完全固定**（133 / 1029 字节），没有长度字段、也没有帧尾定界符 —— 只靠
  起始字节 ``0x01``/``0x02`` 与固定数据长度切帧。库用 ``Field.raw("data", 128)`` 的
  **常量长度** + 同步字节就能正确建模，不强制要长度字段，这点设计是够用的；
* CRC 用 CRC-16/CCITT（多项式 0x1021，初值 0x0000，非反射）；
* 块号与 ``~块号`` 是冗余关系（0xFF - 块号），库不自动校验这种“字段互证”，测试里手判。
"""
from __future__ import annotations

from ..builder import FrameBuilder, Protocol
from ..crc import crc16_ccitt
from ..spec import ChecksumRule, Field, FrameSpec

_XMODEM_CRC = lambda group: crc16_ccitt(group, 0x0000)

SPEC_X = FrameSpec(
    fields=[
        Field.u8("soh", fixed=0x01),
        Field.u8("blk"),
        Field.u8("inv"),
        Field.raw("data", 128),
        Field.checksum("crc", 2, fmt="!H", group="{soh}{blk}{inv}{data}"),
    ],
    payload="data",
    checksum=ChecksumRule("crc", _XMODEM_CRC),
    max_frame_size=133,
    desc="XModem (128-byte blocks)",
)

SPEC_Y = FrameSpec(
    fields=[
        Field.u8("stx", fixed=0x02),
        Field.u8("blk"),
        Field.u8("inv"),
        Field.raw("data", 1024),
        Field.checksum("crc", 2, fmt="!H", group="{stx}{blk}{inv}{data}"),
    ],
    payload="data",
    checksum=ChecksumRule("crc", _XMODEM_CRC),
    max_frame_size=1029,
    desc="YModem (1024-byte blocks)",
)


def protocol_x() -> Protocol:
    return Protocol(SPEC_X)


def protocol_y() -> Protocol:
    return Protocol(SPEC_Y)


def build_xmodem(blk: int, data: bytes) -> bytes:
    """组一条 XModem 块（data 必须正好 128 字节）。"""
    if len(data) != 128:
        raise ValueError("XModem 数据块必须 128 字节")
    return FrameBuilder(SPEC_X).build_raw(None, data, blk=blk, inv=(0xFF - blk) & 0xFF)


def build_ymodem(blk: int, data: bytes) -> bytes:
    """组一条 YModem 块（data 必须正好 1024 字节）。"""
    if len(data) != 1024:
        raise ValueError("YModem 数据块必须 1024 字节")
    return FrameBuilder(SPEC_Y).build_raw(None, data, blk=blk, inv=(0xFF - blk) & 0xFF)
